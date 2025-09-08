using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using GoDaddy.Asherah.AppEncryption.Exceptions;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.Crypto.BufferUtils;
using GoDaddy.Asherah.Crypto.Engine.BouncyCastle;
using GoDaddy.Asherah.Crypto.Keys;
using Microsoft.Extensions.Logging;

namespace GoDaddy.Asherah.AppEncryption.Extensions.Aws.Kms
{
    /// <summary>
    /// AWS-specific implementation of <see cref="IKeyManagementService"/>.
    /// </summary>
    public sealed class KeyManagementService : IKeyManagementService, IDisposable
    {
        private readonly KeyManagementServiceOptions _kmsOptions;
        private readonly IKeyManagementClientFactory _clientFactory;
        private readonly IReadOnlyList<KmsArnClient> _kmsArnClients;
        private readonly ILogger _logger;
        private readonly BouncyAes256GcmCrypto _crypto = new BouncyAes256GcmCrypto();

        private static readonly Action<ILogger, string, Exception> LogFailedGenerateDataKey = LoggerMessage.Define<string>(
            LogLevel.Warning,
            new EventId(1, nameof(KeyManagementService)),
            "Failed to generate data key via ARN {Arn} KMS, trying next ARN");

        private static readonly Action<ILogger, Exception> LogEncryptError = LoggerMessage.Define(
            LogLevel.Error,
            new EventId(2, nameof(KeyManagementService)),
            "Unexpected execution exception while encrypting KMS data key");

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyManagementService"/> class.
        /// </summary>
        /// <param name="kmsOptions">Key Management Service configuration options.</param>
        /// <param name="clientFactory">Factory for creating KMS clients for specific regions.</param>
        /// <param name="loggerFactory">Factory for creating loggers.</param>
        public KeyManagementService(KeyManagementServiceOptions kmsOptions, IKeyManagementClientFactory clientFactory, ILoggerFactory loggerFactory)
        {
            _kmsOptions = kmsOptions;
            _clientFactory = clientFactory;
            _logger = loggerFactory.CreateLogger<KeyManagementService>();

            // Build out the KMS ARN clients
            var kmsArnClients = new List<KmsArnClient>();

            foreach (var regionKeyArn in kmsOptions.RegionKeyArns)
            {
                var client = clientFactory.CreateForRegion(regionKeyArn.Region);
                kmsArnClients.Add(new KmsArnClient(regionKeyArn.KeyArn, client, regionKeyArn.Region));
            }

            _kmsArnClients = kmsArnClients.AsReadOnly();
        }

        /// <inheritdoc/>
        public byte[] EncryptKey(CryptoKey key)
        {
            return EncryptKeyAsync(key).GetAwaiter().GetResult();
        }

        /// <inheritdoc/>
        public CryptoKey DecryptKey(byte[] keyCipherText, DateTimeOffset keyCreated, bool revoked)
        {
            return DecryptKeyAsync(keyCipherText, keyCreated, revoked).GetAwaiter().GetResult();
        }

        /// <inheritdoc/>
        public Task<CryptoKey> DecryptKeyAsync(byte[] keyCipherText, DateTimeOffset keyCreated, bool revoked)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public async Task<byte[]> EncryptKeyAsync(CryptoKey key)
        {
            var (dataKey, dataKeyKeyId) = await GenerateDataKeyAsync();
            byte[] dataKeyPlainText = dataKey.Plaintext.GetBuffer();

            try
            {
                var dataKeyCryptoKey = _crypto.GenerateKeyFromBytes(dataKeyPlainText);
                byte[] encryptedKey = _crypto.EncryptKey(key, dataKeyCryptoKey);

                var kmsKeyEnvelope = new KmsKeyEnvelope
                {
                    EncryptedKey = Convert.ToBase64String(encryptedKey)
                };

                foreach (var kmsArnClient in _kmsArnClients)
                {
                    if (!kmsArnClient.Arn.Equals(dataKeyKeyId, StringComparison.Ordinal))
                    {
                        // If the ARN is different than the datakey's, call encrypt since it's another region
                        var kmsKek = await CreateKmsKek(kmsArnClient, dataKeyPlainText);
                        kmsKeyEnvelope.KmsKeks.Add(kmsKek);
                    }
                    else
                    {
                        // This is the datakey, so build kmsKey json for it
                        var kmsKek = new KmsKek
                        {
                            Region = kmsArnClient.Region,
                            Arn = kmsArnClient.Arn,
                            EncryptedKek = Convert.ToBase64String(dataKey.CiphertextBlob.GetBuffer())
                        };
                        kmsKeyEnvelope.KmsKeks.Add(kmsKek);
                    }
                }

                return JsonSerializer.SerializeToUtf8Bytes(kmsKeyEnvelope);
            }
            catch (Exception ex)
            {
                LogEncryptError(_logger, ex);
                throw new KmsException("unexpected execution error during encrypt");
            }
            finally
            {
                ManagedBufferUtils.WipeByteArray(dataKeyPlainText);
            }
        }

        /// <summary>
        /// Generates a KMS data key for encryption.
        /// </summary>
        /// <returns>A tuple containing the response and the key ID used for the data key.</returns>
        private async Task<(GenerateDataKeyResponse response, string dataKeyKeyId)> GenerateDataKeyAsync()
        {
            foreach (var kmsArnClient in _kmsArnClients)
            {
                try
                {
                    var request = new GenerateDataKeyRequest
                    {
                        KeyId = kmsArnClient.Arn,
                        KeySpec = DataKeySpec.AES_256,
                    };

                    var response = await kmsArnClient.Client.GenerateDataKeyAsync(request);
                    return (response, kmsArnClient.Arn);
                }
                catch (Exception ex)
                {
                    LogFailedGenerateDataKey(_logger, kmsArnClient.Arn, ex);
                }
            }

            throw new KmsException("could not successfully generate data key using any regions");
        }

        /// <summary>
        /// Encrypts a data key for a specific region and builds the result.
        /// </summary>
        /// <param name="kmsArnClient">The KMS ARN client containing client, region, and ARN.</param>
        /// <param name="dataKeyPlainText">The plaintext data key to encrypt.</param>
        /// <returns>A KmsKek object containing the encrypted result.</returns>
        private static async Task<KmsKek> CreateKmsKek(
            KmsArnClient kmsArnClient,
            byte[] dataKeyPlainText)
        {
            using (var plaintextStream = new MemoryStream(dataKeyPlainText))
            {
                var encryptRequest = new EncryptRequest
                {
                    KeyId = kmsArnClient.Arn,
                    Plaintext = plaintextStream
                };

                var encryptResponse = await kmsArnClient.Client.EncryptAsync(encryptRequest);

                // Process the response - ciphertext doesn't need wiping
                using (var ciphertextStream = encryptResponse.CiphertextBlob)
                {
                    // Get the ciphertext bytes
                    byte[] ciphertextBytes = new byte[ciphertextStream.Length];
                    ciphertextStream.Position = 0;
                    ciphertextStream.Read(ciphertextBytes, 0, ciphertextBytes.Length);

                    // Create and return the KmsKek object
                    return new KmsKek
                    {
                        Region = kmsArnClient.Region,
                        Arn = kmsArnClient.Arn,
                        EncryptedKek = Convert.ToBase64String(ciphertextBytes)
                    };
                }
            }
        }

        /// <summary>
        /// Private class representing the KMS key envelope structure.
        /// </summary>
        private sealed class KmsKeyEnvelope
        {
            /// <summary>
            /// Gets or sets the encrypted key.
            /// </summary>
            [JsonPropertyName("encryptedKey")]
            public string EncryptedKey { get; set; } = string.Empty;

            /// <summary>
            /// Gets or sets the list of KMS key encryption keys.
            /// </summary>
            [JsonPropertyName("kmsKeks")]
            public List<KmsKek> KmsKeks { get; set; } = new List<KmsKek>();
        }

        /// <summary>
        /// Private class representing a KMS key encryption key entry.
        /// </summary>
        private sealed class KmsKek
        {
            /// <summary>
            /// Gets or sets the AWS region.
            /// </summary>
            [JsonPropertyName("region")]
            public string Region { get; set; } = string.Empty;

            /// <summary>
            /// Gets or sets the KMS key ARN.
            /// </summary>
            [JsonPropertyName("arn")]
            public string Arn { get; set; } = string.Empty;

            /// <summary>
            /// Gets or sets the encrypted key encryption key.
            /// </summary>
            [JsonPropertyName("encryptedKek")]
            public string EncryptedKek { get; set; } = string.Empty;
        }

        /// <summary>
        /// Disposes the resources used by this instance.
        /// </summary>
        public void Dispose()
        {
            _crypto?.Dispose();
        }
    }
}
