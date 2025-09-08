using System;
using System.Text.Json;
using System.Threading.Tasks;
using GoDaddy.Asherah.AppEncryption.Exceptions;
using GoDaddy.Asherah.AppEncryption.Metastore;
using GoDaddy.Asherah.AppEncryption.Serialization;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.Crypto.Envelope;
using GoDaddy.Asherah.Crypto.Keys;
using GoDaddy.Asherah.Crypto;
using GoDaddy.Asherah.Crypto.Exceptions;
using Microsoft.Extensions.Logging;

using MetastoreKeyMeta = GoDaddy.Asherah.AppEncryption.Metastore.KeyMeta;

namespace GoDaddy.Asherah.AppEncryption.Envelope
{
    /// <summary>
    /// Internal implementation of <see cref="IEnvelopeEncryption{T}"/> that uses byte[] as the Data Row Record format.
    /// This class will eventually replace the current EnvelopeEncryptionBytesImpl to support the new IKeyMetastore integration.
    /// </summary>
    internal sealed class EnvelopeEncryption : IEnvelopeEncryption<byte[]>
    {
        private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            Converters = {
                new InterfaceConverter<DataRowRecordKey, IKeyRecord>(),
                new InterfaceConverter<MetastoreKeyMeta, IKeyMeta>()
            }
        };

        private readonly Partition _partition;
        private readonly AeadEnvelopeCrypto _crypto;
        private readonly IKeyMetastore _metastore;
        private readonly SecureCryptoKeyDictionary<DateTimeOffset> _systemKeyCache;
        private readonly SecureCryptoKeyDictionary<DateTimeOffset> _intermediateKeyCache;
        private readonly CryptoPolicy _cryptoPolicy;
        private readonly IKeyManagementService _keyManagementService;
        private readonly ILogger _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="EnvelopeEncryption"/> class.
        /// </summary>
        /// <param name="partition">The partition for this envelope encryption instance.</param>
        /// <param name="crypto">The crypto implementation for envelope operations.</param>
        /// <param name="cryptoPolicy">Policy that dictates crypto behaviors.</param>
        /// <param name="metastore">The metastore for storing and retrieving keys.</param>
        /// <param name="systemKeyCache">Cache for system keys.</param>
        /// <param name="intermediateKeyCache">Cache for intermediate keys.</param>
        /// <param name="keyManagementService">Service for key management operations.</param>
        /// <param name="logger">The logger implementation to use.</param>
        public EnvelopeEncryption(
            Partition partition,
            AeadEnvelopeCrypto crypto,
            CryptoPolicy cryptoPolicy,
            IKeyMetastore metastore,
            SecureCryptoKeyDictionary<DateTimeOffset> systemKeyCache,
            SecureCryptoKeyDictionary<DateTimeOffset> intermediateKeyCache,
            IKeyManagementService keyManagementService,
            ILogger logger)
        {
            _partition = partition;
            _crypto = crypto;
            _cryptoPolicy = cryptoPolicy;
            _metastore = metastore;
            _systemKeyCache = systemKeyCache;
            _intermediateKeyCache = intermediateKeyCache;
            _keyManagementService = keyManagementService;
            _logger = logger;
        }

        /// <inheritdoc/>
        public byte[] DecryptDataRowRecord(byte[] dataRowRecord)
        {
            return DecryptDataRowRecordAsync(dataRowRecord).GetAwaiter().GetResult();
        }

        /// <inheritdoc/>
        public byte[] EncryptPayload(byte[] payload)
        {
            throw new NotImplementedException("Implementation will be added later");
        }

        /// <inheritdoc/>
        public async Task<byte[]> DecryptDataRowRecordAsync(byte[] dataRowRecord)
        {
            DataRowRecord dataRowRecordModel = DeserializeDataRowRecord(dataRowRecord);

            if (dataRowRecordModel.Key?.ParentKeyMeta == null)
            {
                throw new MetadataMissingException("Could not find parentKeyMeta {IK} for dataRowKey");
            }

            if (!_partition.IsValidIntermediateKeyId(dataRowRecordModel.Key.ParentKeyMeta.KeyId))
            {
                throw new MetadataMissingException("Could not find parentKeyMeta {IK} for dataRowKey");
            }

            // the Data property is a base64 encoded string containing the encrypted payload
            // the Key property from the DataRowRecord.Key is a base64 encoded string containing the encrypted key
            byte[] payloadEncrypted = Convert.FromBase64String(dataRowRecordModel.Data);
            byte[] encryptedKey = Convert.FromBase64String(dataRowRecordModel.Key.Key);

            byte[] decryptedPayload = await WithIntermediateKeyForRead(
                dataRowRecordModel.Key.ParentKeyMeta,
                intermediateCryptoKey =>
                    _crypto.EnvelopeDecrypt(
                        payloadEncrypted,
                        encryptedKey,
                        dataRowRecordModel.Key.Created,
                        intermediateCryptoKey));

            return decryptedPayload;
        }

        /// <inheritdoc/>
        public Task<byte[]> EncryptPayloadAsync(byte[] payload)
        {
            throw new NotImplementedException("Implementation will be added later");
        }

        /// <summary>
        /// Executes a function with the intermediate key for read operations.
        /// </summary>
        /// <param name="intermediateKeyMeta">intermediate key meta used previously to write a DRR.</param>
        /// <param name="functionWithIntermediateKey">the function to call using the decrypted intermediate key.</param>
        /// <returns>The result of the function execution.</returns>
        private async Task<byte[]> WithIntermediateKeyForRead(
            IKeyMeta intermediateKeyMeta, Func<CryptoKey, byte[]> functionWithIntermediateKey)
        {
            CryptoKey intermediateKey = _intermediateKeyCache.Get(intermediateKeyMeta.Created);

            if (intermediateKey == null)
            {
                intermediateKey = await GetIntermediateKey(intermediateKeyMeta);

                // Put the key into our cache if allowed
                if (_cryptoPolicy.CanCacheIntermediateKeys())
                {
                    try
                    {
                        intermediateKey = _intermediateKeyCache.PutAndGetUsable(intermediateKey.GetCreated(), intermediateKey);
                    }
                    catch (Exception ex)
                    {
                        DisposeKey(intermediateKey, ex);
                        throw new AppEncryptionException("Unable to update cache for Intermediate key", ex);
                    }
                }
            }

            return await ApplyFunctionAndDisposeKey(intermediateKey, key => Task.FromResult(functionWithIntermediateKey(key)));
        }

        /// <summary>
        /// Fetches a known intermediate key from metastore and decrypts it using its associated system key.
        /// </summary>
        ///
        /// <returns>The decrypted intermediate key.</returns>
        ///
        /// <param name="intermediateKeyMeta">The <see cref="IKeyMeta"/> of intermediate key.</param>
        /// <exception cref="MetadataMissingException">If the intermediate key is not found, or it has missing system
        /// key info.</exception>
        private async Task<CryptoKey> GetIntermediateKey(IKeyMeta intermediateKeyMeta)
        {
            var (found, intermediateKeyRecord) = await _metastore.TryLoadAsync(intermediateKeyMeta.KeyId, intermediateKeyMeta.Created);

            if (!found)
            {
                throw new MetadataMissingException($"Could not find EnvelopeKeyRecord with keyId = {intermediateKeyMeta.KeyId}, created = {intermediateKeyMeta.Created}");
            }

            if (intermediateKeyRecord.ParentKeyMeta == null)
            {
                throw new MetadataMissingException("Could not find parentKeyMeta (SK) for intermediateKey");
            }

            return await WithExistingSystemKey(
                intermediateKeyRecord.ParentKeyMeta,
                false, // treatExpiredAsMissing = false (allow expired keys)
                systemKey => Task.FromResult(DecryptKey(intermediateKeyRecord, systemKey)));
        }

        /// <summary>
        /// Calls a function using a decrypted system key that was previously used.
        /// </summary>
        /// <typeparam name="T">The type that the <paramref name="functionWithSystemKey"/> returns.</typeparam>
        ///
        /// <returns>The result returned by the <paramref name="functionWithSystemKey"/>.</returns>
        ///
        /// <param name="systemKeyMeta">system key meta used previously to write an IK.</param>
        /// <param name="treatExpiredAsMissing">if <value>true</value>, will throw a
        /// <see cref="MetadataMissingException"/> if the key is expired/revoked.</param>
        /// <param name="functionWithSystemKey">the function to call using the decrypted system key.</param>
        ///
        /// <exception cref="MetadataMissingException">If the system key is not found, or if its expired/revoked and
        /// <see cref="treatExpiredAsMissing"/> is <value>true</value>.</exception>
        private async Task<T> WithExistingSystemKey<T>(
            IKeyMeta systemKeyMeta, bool treatExpiredAsMissing, Func<CryptoKey, Task<T>> functionWithSystemKey)
        {
            // Get from cache or lookup previously used key
            CryptoKey systemKey = _systemKeyCache.Get(systemKeyMeta.Created);

            if (systemKey == null)
            {
                systemKey = await GetSystemKey(systemKeyMeta);

                // Put the key into our cache if allowed
                if (_cryptoPolicy.CanCacheSystemKeys())
                {
                    try
                    {
                        systemKey = _systemKeyCache.PutAndGetUsable(systemKeyMeta.Created, systemKey);
                    }
                    catch (Exception ex)
                    {
                        DisposeKey(systemKey, ex);
                        throw new AppEncryptionException("Unable to update cache for SystemKey", ex);
                    }
                }
            }

            if (IsKeyExpiredOrRevoked(systemKey))
            {
                if (treatExpiredAsMissing)
                {
                    DisposeKey(systemKey, null);
                    throw new MetadataMissingException("System key is expired/revoked, keyMeta = " + systemKeyMeta);
                }
            }

            return await ApplyFunctionAndDisposeKey(systemKey, functionWithSystemKey);
        }

        /// <summary>
        /// Fetches a known system key from metastore and decrypts it using the key management service.
        /// </summary>
        ///
        /// <returns>The decrypted system key.</returns>
        ///
        /// <param name="systemKeyMeta">The <see cref="IKeyMeta"/> of the system key.</param>
        /// <exception cref="MetadataMissingException">If the system key is not found.</exception>
        private async Task<CryptoKey> GetSystemKey(IKeyMeta systemKeyMeta)
        {
            var (found, systemKeyRecord) = await _metastore.TryLoadAsync(systemKeyMeta.KeyId, systemKeyMeta.Created);

            if (!found)
            {
                throw new MetadataMissingException($"Could not find EnvelopeKeyRecord with keyId = {systemKeyMeta.KeyId}, created = {systemKeyMeta.Created}");
            }

            return _keyManagementService.DecryptKey(
                Convert.FromBase64String(systemKeyRecord.Key),
                systemKeyRecord.Created,
                systemKeyRecord.Revoked ?? false);
        }

        /// <summary>
        /// Decrypts the <paramref name="keyRecord"/>'s encrypted key using the provided key.
        /// </summary>
        ///
        /// <returns>The decrypted key contained in the <paramref name="keyRecord"/>.</returns>
        ///
        /// <param name="keyRecord">The key to decrypt.</param>
        /// <param name="keyEncryptionKey">Encryption key to use for decryption.</param>
        private CryptoKey DecryptKey(IKeyRecord keyRecord, CryptoKey keyEncryptionKey)
        {
            return _crypto.DecryptKey(
                Convert.FromBase64String(keyRecord.Key),
                keyRecord.Created,
                keyEncryptionKey,
                keyRecord.Revoked ?? false);
        }

        /// <summary>
        /// Checks if a key is expired or revoked.
        /// </summary>
        /// <param name="cryptoKey">The crypto key to check.</param>
        /// <returns>True if the key is expired or revoked, false otherwise.</returns>
        private bool IsKeyExpiredOrRevoked(CryptoKey cryptoKey)
        {
            return _cryptoPolicy.IsKeyExpired(cryptoKey.GetCreated()) || cryptoKey.IsRevoked();
        }

        /// <summary>
        /// Applies a function with a crypto key and ensures the key is properly disposed afterward.
        /// </summary>
        /// <param name="key">The crypto key to use.</param>
        /// <param name="functionWithKey">The function to execute with the key.</param>
        /// <returns>The result of the function execution.</returns>
        private static async Task<T> ApplyFunctionAndDisposeKey<T>(CryptoKey key, Func<CryptoKey, Task<T>> functionWithKey)
        {
            try
            {
                return await functionWithKey(key);
            }
            catch (Exception ex)
            {
                throw new AppEncryptionException($"Failed call action method, error: {ex.Message}", ex);
            }
            finally
            {
                DisposeKey(key, null);
            }
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            try
            {
                // only close intermediate key cache since its lifecycle is tied to this "session"
                _intermediateKeyCache.Dispose();
            }
            catch (Exception ex)
            {
                _logger?.LogError(ex, "Unexpected exception during dispose");
            }
        }

        /// <summary>
        /// Disposes a crypto key with proper error handling.
        /// </summary>
        /// <param name="cryptoKey">The key to dispose.</param>
        /// <param name="rootException">The root exception that caused the disposal, if any.</param>
        private static void DisposeKey(CryptoKey cryptoKey, Exception rootException)
        {
            try
            {
                cryptoKey.Dispose();
            }
            catch (Exception ex)
            {
                if (rootException != null)
                {
                    AggregateException aggregateException = new AggregateException(ex, rootException);
                    throw new AppEncryptionException(
                        $"Failed to dispose/wipe key, error: {ex.Message}", aggregateException);
                }

                throw new AppEncryptionException($"Failed to dispose/wipe key, error: {ex.Message}", ex);
            }
        }


        /// <summary>
        /// Deserializes a byte array containing UTF-8 JSON into a strongly-typed DataRowRecord.
        /// </summary>
        ///
        /// <param name="dataRowRecordBytes">The UTF-8 encoded JSON bytes representing the DataRowRecord.</param>
        /// <returns>A deserialized DataRowRecord object.</returns>
        private static DataRowRecord DeserializeDataRowRecord(byte[] dataRowRecordBytes)
        {
            if (dataRowRecordBytes == null || dataRowRecordBytes.Length == 0)
            {
                throw new ArgumentException("DataRowRecord bytes cannot be null or empty", nameof(dataRowRecordBytes));
            }

            DataRowRecord result;
            try
            {
                result = JsonSerializer.Deserialize<DataRowRecord>(dataRowRecordBytes, JsonOptions);
            }
            catch (JsonException ex)
            {
                throw new ArgumentException("Invalid JSON format in DataRowRecord bytes", nameof(dataRowRecordBytes), ex);
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Failed to deserialize DataRowRecord", nameof(dataRowRecordBytes), ex);
            }

            if (result == null)
            {
                throw new ArgumentException("Deserialized DataRowRecord cannot be null", nameof(dataRowRecordBytes));
            }

            return result;
        }
    }
}
