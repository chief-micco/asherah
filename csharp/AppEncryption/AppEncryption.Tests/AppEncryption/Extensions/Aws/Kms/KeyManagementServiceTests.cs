using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using GoDaddy.Asherah.AppEncryption.Extensions.Aws.Kms;
using GoDaddy.Asherah.AppEncryption.Tests.AppEncryption.TestHelpers;
using GoDaddy.Asherah.Crypto.Engine.BouncyCastle;
using GoDaddy.Asherah.Crypto.ExtensionMethods;
using GoDaddy.Asherah.Crypto.Keys;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace GoDaddy.Asherah.AppEncryption.Tests.AppEncryption.Extensions.Aws.Kms
{
    [ExcludeFromCodeCoverage]
    public class KeyManagementServiceTests : IDisposable
    {
        private const string UsEast1 = "us-east-1";
        private const string ArnUsEast1 = "arn-us-east-1";
        private const string UsWest1 = "us-west-1";
        private const string ArnUsWest1 = "arn-us-west-1";

        private readonly KeyManagementServiceOptions _keyManagementServiceOptions;
        private readonly KeyManagementService _keyManagementService;
        private readonly LoggerFactoryStub _loggerFactoryStub;
        private readonly KeyManagementClientFactoryStub _clientFactoryStub;

        public KeyManagementServiceTests()
        {
            _keyManagementServiceOptions = new KeyManagementServiceOptions
            {
                RegionKeyArns = new List<RegionKeyArn>
                {
                    new RegionKeyArn { Region = UsEast1, KeyArn = ArnUsEast1 },
                    new RegionKeyArn { Region = UsWest1, KeyArn = ArnUsWest1 }
                }
            };

            _loggerFactoryStub = new LoggerFactoryStub();
            _clientFactoryStub = new KeyManagementClientFactoryStub(_keyManagementServiceOptions);
            _keyManagementService = new KeyManagementService(_keyManagementServiceOptions, _clientFactoryStub, _loggerFactoryStub);
        }

        [Fact]
        public async Task EncryptKeyAsync_ShouldEncryptKey()
        {
            // Arrange
            using var crypto = new BouncyAes256GcmCrypto();
            var keyCreationTime = DateTimeOffset.UtcNow.Truncate(TimeSpan.FromMinutes(1));
            using var key = crypto.GenerateKey(keyCreationTime);

            // Act
            var result = await _keyManagementService.EncryptKeyAsync(key);

            // Assert
            Assert.NotNull(result);

            // Deserialize and validate JSON structure
            var jsonNode = System.Text.Json.Nodes.JsonNode.Parse(result);

            // Assert JSON structure
            Assert.NotNull(jsonNode);
            Assert.True(jsonNode is System.Text.Json.Nodes.JsonObject);

            var jsonObject = jsonNode.AsObject();

            // Assert encryptedKey exists and is not empty
            Assert.True(jsonObject.ContainsKey("encryptedKey"));
            var encryptedKey = jsonObject["encryptedKey"];
            Assert.NotNull(encryptedKey);
            Assert.True(encryptedKey is System.Text.Json.Nodes.JsonValue);
            var encryptedKeyValue = encryptedKey!.AsValue().GetValue<string>();
            Assert.NotNull(encryptedKeyValue);
            Assert.NotEmpty(encryptedKeyValue);

            // Assert kmsKeks exists and is an array
            Assert.True(jsonObject.ContainsKey("kmsKeks"));
            var kmsKeks = jsonObject["kmsKeks"];
            Assert.NotNull(kmsKeks);
            Assert.True(kmsKeks is System.Text.Json.Nodes.JsonArray);

            var kmsKeksArray = kmsKeks!.AsArray();
            Assert.Equal(2, kmsKeksArray.Count); // Should have 2 regions

            // Assert each KMS KEK has required properties
            foreach (var kekNode in kmsKeksArray)
            {
                Assert.NotNull(kekNode);
                Assert.True(kekNode is System.Text.Json.Nodes.JsonObject);

                var kekObject = kekNode!.AsObject();

                // Assert region exists
                Assert.True(kekObject.ContainsKey("region"));
                var region = kekObject["region"];
                Assert.NotNull(region);
                var regionValue = region!.AsValue().GetValue<string>();
                Assert.NotNull(regionValue);
                Assert.True(regionValue == "us-east-1" || regionValue == "us-west-1");

                // Assert arn exists
                Assert.True(kekObject.ContainsKey("arn"));
                var arn = kekObject["arn"];
                Assert.NotNull(arn);
                var arnValue = arn!.AsValue().GetValue<string>();
                Assert.NotNull(arnValue);
                Assert.True(arnValue == "arn-us-east-1" || arnValue == "arn-us-west-1");

                // Assert encryptedKek exists and is not empty
                Assert.True(kekObject.ContainsKey("encryptedKek"));
                var encryptedKek = kekObject["encryptedKek"];
                Assert.NotNull(encryptedKek);
                var encryptedKekValue = encryptedKek!.AsValue().GetValue<string>();
                Assert.NotNull(encryptedKekValue);
                Assert.NotEmpty(encryptedKekValue);
            }

            // Assert we have both regions
            var regions = kmsKeksArray.Select(kek => kek!.AsObject()["region"]!.AsValue().GetValue<string>()).ToList();
            Assert.Contains("us-east-1", regions);
            Assert.Contains("us-west-1", regions);
        }

        [Fact]
        public async Task DecryptKeyAsync_ShouldDecryptKey()
        {
            // Arrange
            using var crypto = new BouncyAes256GcmCrypto();
            var keyCreationTime = DateTimeOffset.UtcNow.Truncate(TimeSpan.FromMinutes(1));
            using var originalKey = crypto.GenerateKey(keyCreationTime);

            // Act
            var encryptedResult = await _keyManagementService.EncryptKeyAsync(originalKey);
            var decryptedKey = await _keyManagementService.DecryptKeyAsync(encryptedResult, keyCreationTime, revoked: false);

            // Assert
            Assert.NotNull(decryptedKey);
        }

        public void Dispose()
        {
            _keyManagementService?.Dispose();
        }
    }
}
