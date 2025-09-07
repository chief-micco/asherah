using System;
using System.Text.Json;
using GoDaddy.Asherah.AppEncryption.Exceptions;
using GoDaddy.Asherah.AppEncryption.Metastore;
using GoDaddy.Asherah.AppEncryption.Serialization;
using GoDaddy.Asherah.Crypto.Envelope;
using GoDaddy.Asherah.Crypto.Keys;

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

        /// <summary>
        /// Initializes a new instance of the <see cref="EnvelopeEncryption"/> class.
        /// </summary>
        /// <param name="partition">The partition for this envelope encryption instance.</param>
        /// <param name="crypto">The crypto implementation for envelope operations.</param>
        public EnvelopeEncryption(Partition partition, AeadEnvelopeCrypto crypto)
        {
            _partition = partition;
            _crypto = crypto;
        }

        /// <inheritdoc/>
        public byte[] DecryptDataRowRecord(byte[] dataRowRecord)
        {
            // Step 1: Deserialize the byte array into a strongly-typed DataRowRecord
            DataRowRecord dataRowRecordModel = DeserializeDataRowRecord(dataRowRecord);

            // Step 2: Validate that we have ParentKeyMeta
            if (dataRowRecordModel.Key?.ParentKeyMeta == null)
            {
                throw new MetadataMissingException("Could not find parentKeyMeta {IK} for dataRowKey");
            }

            // Step 3: Validate intermediate key ID against partition
            if (!_partition.IsValidIntermediateKeyId(dataRowRecordModel.Key.ParentKeyMeta.KeyId))
            {
                throw new MetadataMissingException("Could not find parentKeyMeta {IK} for dataRowKey");
            }

            // Step 4: Extract encrypted payload and key from base64 strings
            byte[] payloadEncrypted = Convert.FromBase64String(dataRowRecordModel.Data);
            byte[] encryptedKey = Convert.FromBase64String(dataRowRecordModel.Key.Key);

            // Step 5: Decrypt using intermediate key
            byte[] decryptedPayload = WithIntermediateKeyForRead(
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
        public byte[] EncryptPayload(byte[] payload)
        {
            throw new NotImplementedException("Implementation will be added later");
        }

        /// <summary>
        /// Executes a function with the intermediate key for read operations.
        /// </summary>
        /// <param name="intermediateKeyMeta">intermediate key meta used previously to write a DRR.</param>
        /// <param name="functionWithIntermediateKey">the function to call using the decrypted intermediate key.</param>
        /// <returns>The result of the function execution.</returns>
        private byte[] WithIntermediateKeyForRead(
            IKeyMeta intermediateKeyMeta, Func<CryptoKey, byte[]> functionWithIntermediateKey)
        {
            throw new NotImplementedException("Implementation will be added later");
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            // Implementation will be added later
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
