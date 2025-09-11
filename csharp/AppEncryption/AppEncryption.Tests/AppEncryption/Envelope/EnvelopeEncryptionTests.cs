using System;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using GoDaddy.Asherah.AppEncryption.Envelope;
using GoDaddy.Asherah.AppEncryption.Exceptions;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Metastore;
using GoDaddy.Asherah.AppEncryption.Tests.AppEncryption.TestHelpers.Dummy;
using GoDaddy.Asherah.Crypto;
using GoDaddy.Asherah.Crypto.Engine.BouncyCastle;
using GoDaddy.Asherah.Crypto.Keys;
using Xunit;

namespace GoDaddy.Asherah.AppEncryption.Tests.AppEncryption.Envelope;

[ExcludeFromCodeCoverage]
public class EnvelopeEncryptionTests
{
    private readonly DefaultPartition _partition = new("defaultPartition", "testService", "testProduct");

    private EnvelopeEncryption NewEnvelopeEncryption(
        CryptoPolicy cryptoPolicy = null,
        IKeyManagementService keyManagementService = null,
        IKeyMetastore metastore = null,
        Partition partition = null)
    {
        metastore ??= new InMemoryKeyMetastore();
        var loggerFactory = new TestHelpers.LoggerFactoryStub();
        var logger = loggerFactory.CreateLogger("EnvelopeEncryptionTests");
        keyManagementService ??= new DummyKeyManagementService();
        var crypto = new BouncyAes256GcmCrypto();
        partition ??= _partition;

        cryptoPolicy ??= BasicExpiringCryptoPolicy.NewBuilder()
            .WithKeyExpirationDays(30)
            .WithRevokeCheckMinutes(30)
            .WithCanCacheIntermediateKeys(true)
            .WithCanCacheSystemKeys(true)
            .WithCanCacheSessions(false)
            .Build();

        var systemKeyCache = new SecureCryptoKeyDictionary<DateTimeOffset>(cryptoPolicy.GetRevokeCheckPeriodMillis());
        var intermediateKeyCache = new SecureCryptoKeyDictionary<DateTimeOffset>(cryptoPolicy.GetRevokeCheckPeriodMillis());

        return new EnvelopeEncryption(
            partition,
            metastore,
            keyManagementService,
            crypto,
            cryptoPolicy,
            systemKeyCache,
            intermediateKeyCache,
            logger);
    }

    [Fact]
    public void EncryptDecrypt_WithDefaults_Sync()
    {
        const string inputValue = "The quick brown fox jumps over the lazy dog";
        var inputBytes = System.Text.Encoding.UTF8.GetBytes(inputValue);

        using var envelopeEncryption = NewEnvelopeEncryption();
        var dataRowRecordBytes = envelopeEncryption.EncryptPayload(inputBytes);

        ValidateDataRowRecordJson(dataRowRecordBytes);

        var decryptedBytes = envelopeEncryption.DecryptDataRowRecord(dataRowRecordBytes);
        var outputValue = System.Text.Encoding.UTF8.GetString(decryptedBytes);

        Assert.Equal(inputValue, outputValue);
    }

    [Fact]
    public async Task EncryptDecrypt_WithDefaults()
    {
        const string inputValue = "The quick brown fox jumps over the lazy dog";
        var inputBytes = System.Text.Encoding.UTF8.GetBytes(inputValue);

        using var envelopeEncryption = NewEnvelopeEncryption();
        var dataRowRecordBytes = await envelopeEncryption.EncryptPayloadAsync(inputBytes);

        ValidateDataRowRecordJson(dataRowRecordBytes);

        var decryptedBytes = await envelopeEncryption.DecryptDataRowRecordAsync(dataRowRecordBytes);
        var outputValue = System.Text.Encoding.UTF8.GetString(decryptedBytes);

        Assert.Equal(inputValue, outputValue);
    }

    [Fact]
    public async Task EncryptDecrypt_MultipleTimes_WithDefaults()
    {
        const string inputValue = "The quick brown fox jumps over the lazy dog";
        var inputBytes = System.Text.Encoding.UTF8.GetBytes(inputValue);

        const string inputValue2 = "Lorem ipsum dolor sit amet, consectetur adipiscing elit";
        var inputBytes2 = System.Text.Encoding.UTF8.GetBytes(inputValue2);

        using var envelopeEncryption = NewEnvelopeEncryption();
        var dataRowRecordBytes = await envelopeEncryption.EncryptPayloadAsync(inputBytes);
        var dataRowRecordBytes2 = await envelopeEncryption.EncryptPayloadAsync(inputBytes2);

        ValidateDataRowRecordJson(dataRowRecordBytes);
        ValidateDataRowRecordJson(dataRowRecordBytes2);

        var decryptedBytes = await envelopeEncryption.DecryptDataRowRecordAsync(dataRowRecordBytes);
        var outputValue = System.Text.Encoding.UTF8.GetString(decryptedBytes);

        Assert.Equal(inputValue, outputValue);

        var decryptAgainBytes = await envelopeEncryption.DecryptDataRowRecordAsync(dataRowRecordBytes);
        var outputValueAgain = System.Text.Encoding.UTF8.GetString(decryptAgainBytes);

        Assert.Equal(inputValue, outputValueAgain);

        var decryptedBytes2 = await envelopeEncryption.DecryptDataRowRecordAsync(dataRowRecordBytes2);
        var outputValue2 = System.Text.Encoding.UTF8.GetString(decryptedBytes2);

        Assert.Equal(inputValue2, outputValue2);
    }

    [Fact]
    public async Task EncryptDecrypt_WithDifferentInstances()
    {
        var keyManagementService = new DummyKeyManagementService();
        var metastore = new InMemoryKeyMetastore();
        var cryptoPolicy = BasicExpiringCryptoPolicy.NewBuilder()
            .WithKeyExpirationDays(30)
            .WithRevokeCheckMinutes(30)
            .WithCanCacheIntermediateKeys(false)
            .WithCanCacheSystemKeys(false)
            .WithCanCacheSessions(false)
            .Build();

        const string inputValue = "The quick brown fox jumps over the lazy dog";
        var inputBytes = System.Text.Encoding.UTF8.GetBytes(inputValue);

        using var envelopeEncryption = NewEnvelopeEncryption(cryptoPolicy, keyManagementService, metastore);
        using var envelopeEncryption2 = NewEnvelopeEncryption(cryptoPolicy, keyManagementService, metastore);

        var dataRowRecordBytes = await envelopeEncryption.EncryptPayloadAsync(inputBytes);
        var dataRowRecordBytes2 = await envelopeEncryption2.EncryptPayloadAsync(inputBytes);

        ValidateDataRowRecordJson(dataRowRecordBytes);

        var decryptedBytes = await envelopeEncryption2.DecryptDataRowRecordAsync(dataRowRecordBytes);
        var outputValue = System.Text.Encoding.UTF8.GetString(decryptedBytes);

        Assert.Equal(inputValue, outputValue);

        var decryptedBytes2 = await envelopeEncryption.DecryptDataRowRecordAsync(dataRowRecordBytes2);
        var outputValue2 = System.Text.Encoding.UTF8.GetString(decryptedBytes2);

        Assert.Equal(inputValue, outputValue2);
    }

    [Fact]
    public async Task Decrypt_Throws_When_IntermediateKey_Cannot_Be_Found()
    {
        var keyManagementService = new DummyKeyManagementService();
        var cryptoPolicy = BasicExpiringCryptoPolicy.NewBuilder()
            .WithKeyExpirationDays(30)
            .WithRevokeCheckMinutes(30)
            .WithCanCacheIntermediateKeys(false)
            .WithCanCacheSystemKeys(false)
            .WithCanCacheSessions(false)
            .Build();

        const string inputValue = "The quick brown fox jumps over the lazy dog";
        var inputBytes = System.Text.Encoding.UTF8.GetBytes(inputValue);

        using var envelopeEncryption = NewEnvelopeEncryption(cryptoPolicy, keyManagementService);

        // new instance will be using an empty metastore
        using var envelopeEncryption2 = NewEnvelopeEncryption(cryptoPolicy, keyManagementService);

        var dataRowRecordBytes = await envelopeEncryption.EncryptPayloadAsync(inputBytes);

        await Assert.ThrowsAsync<MetadataMissingException>(async () =>
        {
            await envelopeEncryption2.DecryptDataRowRecordAsync(dataRowRecordBytes);
        });

    }


    [Theory]
    [MemberData(nameof(GetCryptoPolicies))]
    public async Task EncryptDecrypt_WithVariousCryptoPolicies(CryptoPolicy cryptoPolicy)
    {
        const string inputValue = "The quick brown fox jumps over the lazy dog";
        var inputBytes = System.Text.Encoding.UTF8.GetBytes(inputValue);

        using var envelopeEncryption = NewEnvelopeEncryption(cryptoPolicy);
        var dataRowRecordBytes = await envelopeEncryption.EncryptPayloadAsync(inputBytes);

        ValidateDataRowRecordJson(dataRowRecordBytes);

        var decryptedBytes = await envelopeEncryption.DecryptDataRowRecordAsync(dataRowRecordBytes);
        var outputValue = System.Text.Encoding.UTF8.GetString(decryptedBytes);

        Assert.Equal(inputValue, outputValue);

        var decryptAgainBytes = await envelopeEncryption.DecryptDataRowRecordAsync(dataRowRecordBytes);
        var outputValueAgain = System.Text.Encoding.UTF8.GetString(decryptAgainBytes);

        Assert.Equal(inputValue, outputValueAgain);
    }

    public static TheoryData<CryptoPolicy> GetCryptoPolicies()
    {
        return new TheoryData<CryptoPolicy>(
            BasicExpiringCryptoPolicy.NewBuilder()
            .WithKeyExpirationDays(30)
            .WithRevokeCheckMinutes(30)
            .WithCanCacheIntermediateKeys(false)
            .WithCanCacheSystemKeys(false)
            .WithCanCacheSessions(false)
            .Build(),
            BasicExpiringCryptoPolicy.NewBuilder()
            .WithKeyExpirationDays(30)
            .WithRevokeCheckMinutes(30)
            .WithCanCacheIntermediateKeys(false)
            .WithCanCacheSystemKeys(true)
            .WithCanCacheSessions(false)
            .Build(),
            BasicExpiringCryptoPolicy.NewBuilder()
            .WithKeyExpirationDays(30)
            .WithRevokeCheckMinutes(30)
            .WithCanCacheIntermediateKeys(true)
            .WithCanCacheSystemKeys(true)
            .WithCanCacheSessions(false)
            .Build());
    }

    [Fact]
    public async Task Encrypt_Uses_Partitions()
    {
        var partition1 = new DefaultPartition("partition1", "service", "product");
        var partition2 = new DefaultPartition("partition2", "service", "product");

        const string inputValue = "The quick brown fox jumps over the lazy dog";
        var inputBytes = System.Text.Encoding.UTF8.GetBytes(inputValue);

        using var envelopeEncryption1 = NewEnvelopeEncryption(partition: partition1);
        using var envelopeEncryption2 = NewEnvelopeEncryption(partition: partition2);

        var dataRowRecordBytes1 = await envelopeEncryption1.EncryptPayloadAsync(inputBytes);
        var dataRowRecordBytes2 = await envelopeEncryption2.EncryptPayloadAsync(inputBytes);

        Assert.NotEqual(dataRowRecordBytes1, dataRowRecordBytes2);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Not a JSON string")]
    [InlineData("null")] // Missing required fields
    [InlineData("{\"Invalid\":\"Missing required fields\"}", typeof(MetadataMissingException))]
    [InlineData("{\"Key\":null,\"Data\":\"ValidBase64ButKeyIsNull\"}", typeof(MetadataMissingException))]
    [InlineData("{\"Key\":{\"Created\":1752685310,\"Key\":\"ParentKeyMetaIsMissing\"},\"Data\":\"SomeData\"}", typeof(MetadataMissingException))]
    [InlineData("{\"Key\":{\"Created\":1752685310,\"Key\":\"ParentKeyMetaIsNull\",\"ParentKeyMeta\":null},\"Data\":\"SomeData\"}", typeof(MetadataMissingException))]
    [InlineData("{\"Key\":{\"Created\":1752685310,\"Key\":\"ParentKeyKeyIdIsMissing\",\"ParentKeyMeta\":{\"Created\":1752501780}},\"Data\":\"SomeData\"}", typeof(MetadataMissingException))]
    [InlineData("{\"Key\":{\"Created\":1752685310,\"Key\":\"ParentKeyKeyIdIsNull\",\"ParentKeyMeta\":{\"KeyId\":null,\"Created\":1752501780}},\"Data\":\"SomeData\"}", typeof(MetadataMissingException))]
    [InlineData("{\"Key\":{\"Created\":1752685310,\"Key\":\"ParentKeyKeyIdNotValid\",\"ParentKeyMeta\":{\"KeyId\":\"not-valid-key\",\"Created\":1752501780}},\"Data\":\"SomeData\"}", typeof(MetadataMissingException))]
    public async Task Bad_DataRowRecord_Throws(string dataRowRecordString, Type exceptionType = null)
    {
        var badDataRowRecordBytes = System.Text.Encoding.UTF8.GetBytes(dataRowRecordString);

        using var envelopeEncryption = NewEnvelopeEncryption();

        exceptionType ??= typeof(ArgumentException);

        await Assert.ThrowsAsync(exceptionType, async () =>
        {
            await envelopeEncryption.DecryptDataRowRecordAsync(badDataRowRecordBytes);
        });
    }

    private static void ValidateDataRowRecordJson(byte[] dataRowRecordBytes)
    {
        // Deserialize into JsonNode and validate structure matches this format:
        /*
          {
               "Key": {
                   "Created": 1752685310,
                   "Key": "base64-encryptedDataRowKeyByteArray",
                   "ParentKeyMeta": {
                       "KeyId": "_IK_widgets_dotnet-guild-tools_Human-Resources_us-west-2",
                       "Created": 1752501780
                   }
               },
               "Data": "base64-encryptedDataByteArray"
           }
         */
        var dataRowObject = JsonNode.Parse(dataRowRecordBytes);
        Assert.NotNull(dataRowObject);
        Assert.NotNull(dataRowObject["Key"]);
        Assert.Equal(JsonValueKind.Object, dataRowObject["Key"]?.GetValueKind());

        Assert.NotNull(dataRowObject["Data"]);
        Assert.Equal(JsonValueKind.String, dataRowObject["Data"]?.GetValueKind());

        Assert.NotNull(dataRowObject["Key"]?["Created"]);
        Assert.Equal(JsonValueKind.Number, dataRowObject["Key"]?["Created"]?.GetValueKind());

        Assert.NotNull(dataRowObject["Key"]?["Key"]);
        Assert.Equal(JsonValueKind.String, dataRowObject["Key"]?["Key"]?.GetValueKind());

        Assert.NotNull(dataRowObject["Key"]?["ParentKeyMeta"]);
        Assert.Equal(JsonValueKind.Object, dataRowObject["Key"]?["ParentKeyMeta"]?.GetValueKind());

        Assert.NotNull(dataRowObject["Key"]?["ParentKeyMeta"]?["KeyId"]);
        Assert.Equal(JsonValueKind.String, dataRowObject["Key"]?["ParentKeyMeta"]?["KeyId"]?.GetValueKind());

        Assert.NotNull(dataRowObject["Key"]?["ParentKeyMeta"]?["Created"]);
        Assert.Equal(JsonValueKind.Number, dataRowObject["Key"]?["ParentKeyMeta"]?["Created"]?.GetValueKind());
    }
}
