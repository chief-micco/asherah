using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using GoDaddy.Asherah.AppEncryption.Extensions.Aws.Metastore;
using GoDaddy.Asherah.AppEncryption.Metastore;
using GoDaddy.Asherah.AppEncryption.Tests.Fixtures;
using Moq;
using Xunit;

namespace GoDaddy.Asherah.AppEncryption.Tests.Extensions.Aws.Metastore;

public class DynamoDbMetastoreTests : IClassFixture<DynamoDBContainerFixture>, IDisposable
{
    private const string TestTableName = "TestKeysTable";
    private const string TestRegion = "us-west-2";

    private readonly AmazonDynamoDBClient _amazonDynamoDbClient;
    private readonly DynamoDbMetastore _dynamoDbMetastore;
    private readonly DynamoDbMetastoreOptions _options;
    private readonly DateTimeOffset _created;

    public DynamoDbMetastoreTests(DynamoDBContainerFixture dynamoDbContainerFixture)
    {
        string serviceUrl = dynamoDbContainerFixture.GetServiceUrl();
        AmazonDynamoDBConfig clientConfig = new AmazonDynamoDBConfig
        {
            ServiceURL = serviceUrl,
            AuthenticationRegion = TestRegion,
        };
        _amazonDynamoDbClient = new AmazonDynamoDBClient(clientConfig);

        DynamoMetastoreHelper.CreateTableSchema(_amazonDynamoDbClient, TestTableName).Wait();

        _options = new DynamoDbMetastoreOptions(TestTableName);
        _dynamoDbMetastore = new DynamoDbMetastore(_amazonDynamoDbClient, _options);

        // Pre-populate test data using helper and capture the created timestamp
        _created = DynamoMetastoreHelper.PrePopulateTestDataUsingOldMetastore(_amazonDynamoDbClient, TestTableName, TestRegion).Result;
    }

    public void Dispose()
    {
        try
        {
            DeleteTableResponse deleteTableResponse = _amazonDynamoDbClient
                .DeleteTableAsync(TestTableName)
                .Result;
        }
        catch (AggregateException)
        {
            // There is no such table.
        }
    }

    private static void VerifyKeyRecordMatchesExpected(KeyRecord loadedKeyRecord)
    {
        // Test Key property
        Assert.Equal((string)DynamoMetastoreHelper.ExistingKeyRecord["Key"], loadedKeyRecord.Key);

        // Test Created property
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds((long)(int)DynamoMetastoreHelper.ExistingKeyRecord["Created"]), loadedKeyRecord.Created);

        // Test Revoked property (should be null since not in test data)
        Assert.Null(loadedKeyRecord.Revoked);

        // Test ParentKeyMeta property
        Assert.NotNull(loadedKeyRecord.ParentKeyMeta);
        var expectedParentKeyMeta = (Dictionary<string, object>)DynamoMetastoreHelper.ExistingKeyRecord["ParentKeyMeta"];
        Assert.Equal((string)expectedParentKeyMeta["KeyId"], loadedKeyRecord.ParentKeyMeta.Id);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds((long)(int)expectedParentKeyMeta["Created"]), loadedKeyRecord.ParentKeyMeta.Created);
    }

    private DynamoDbMetastore CreateMetastoreWithBrokenDynamoClient()
    {
        var mockDynamoDbClient = new Mock<IAmazonDynamoDB>();

        // Mock GetItemAsync to throw generic Exception
        mockDynamoDbClient.Setup(x => x.GetItemAsync(It.IsAny<GetItemRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("boom!"));

        // Mock QueryAsync to throw generic Exception
        mockDynamoDbClient.Setup(x => x.QueryAsync(It.IsAny<QueryRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("boom!"));

        return new DynamoDbMetastore(mockDynamoDbClient.Object, _options);
    }

    private DynamoDbMetastore CreateMetastoreWithBrokenDynamoClientForStore()
    {
        var mockDynamoDbClient = new Mock<IAmazonDynamoDB>();

        // Mock PutItemAsync to throw generic Exception for Store operations
        mockDynamoDbClient.Setup(x => x.PutItemAsync(It.IsAny<PutItemRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new Exception("boom!"));

        return new DynamoDbMetastore(mockDynamoDbClient.Object, _options);
    }

    [Fact]
    public async Task TestLoadSuccess()
    {
        var (found, loadedKeyRecord) = await _dynamoDbMetastore.TryLoadAsync(DynamoMetastoreHelper.ExistingTestKey, _created);

        Assert.True(found);
        Assert.NotNull(loadedKeyRecord);
        VerifyKeyRecordMatchesExpected(loadedKeyRecord);
    }

    [Fact]
    public async Task TestLoadWithNoResultShouldReturnFalse()
    {
        var (found, loadedKeyRecord) = await _dynamoDbMetastore.TryLoadAsync("fake_key", _created);

        Assert.False(found);
        Assert.Null(loadedKeyRecord);
    }

    [Fact]
    public async Task TestLoadLatestWithSingleRecord()
    {
        var (found, loadedKeyRecord) = await _dynamoDbMetastore.TryLoadLatestAsync(DynamoMetastoreHelper.ExistingTestKey);

        Assert.True(found);
        Assert.NotNull(loadedKeyRecord);
        VerifyKeyRecordMatchesExpected(loadedKeyRecord);
    }

    [Fact]
    public async Task TestLoadLatestWithNoResultShouldReturnFalse()
    {
        var (found, loadedKeyRecord) = await _dynamoDbMetastore.TryLoadLatestAsync("fake_key");

        Assert.False(found);
        Assert.Null(loadedKeyRecord);
    }

    [Fact]
    public async Task TestLoadLatestWithMultipleRecords()
    {
        // Create multiple records with different timestamps
        DateTimeOffset createdMinusOneHour = _created.AddHours(-1);
        DateTimeOffset createdPlusOneHour = _created.AddHours(1);
        DateTimeOffset createdMinusOneDay = _created.AddDays(-1);
        DateTimeOffset createdPlusOneDay = _created.AddDays(1);

        // Create test KeyRecord objects
        var keyRecordMinusOneHour = new KeyRecord(createdMinusOneHour, "key_minus_one_hour", null, null);
        var keyRecordPlusOneHour = new KeyRecord(createdPlusOneHour, "key_plus_one_hour", null, null);
        var keyRecordMinusOneDay = new KeyRecord(createdMinusOneDay, "key_minus_one_day", null, null);
        var keyRecordPlusOneDay = new KeyRecord(createdPlusOneDay, "key_plus_one_day", null, null);

        // Insert records using the old metastore (intentionally mixing up insertion order)
        await DynamoMetastoreHelper.AddKeyRecordUsingOldMetastore(_amazonDynamoDbClient, TestTableName, TestRegion, DynamoMetastoreHelper.ExistingTestKey, createdPlusOneHour, keyRecordPlusOneHour);
        await DynamoMetastoreHelper.AddKeyRecordUsingOldMetastore(_amazonDynamoDbClient, TestTableName, TestRegion, DynamoMetastoreHelper.ExistingTestKey, createdPlusOneDay, keyRecordPlusOneDay);
        await DynamoMetastoreHelper.AddKeyRecordUsingOldMetastore(_amazonDynamoDbClient, TestTableName, TestRegion, DynamoMetastoreHelper.ExistingTestKey, createdMinusOneHour, keyRecordMinusOneHour);
        await DynamoMetastoreHelper.AddKeyRecordUsingOldMetastore(_amazonDynamoDbClient, TestTableName, TestRegion, DynamoMetastoreHelper.ExistingTestKey, createdMinusOneDay, keyRecordMinusOneDay);

        // Test that LoadLatest returns the record with the latest timestamp
        var (found, loadedKeyRecord) = await _dynamoDbMetastore.TryLoadLatestAsync(DynamoMetastoreHelper.ExistingTestKey);

        Assert.True(found);
        Assert.NotNull(loadedKeyRecord);
        Assert.Equal("key_plus_one_day", loadedKeyRecord.Key);
        // Compare Unix timestamps since DynamoDB stores timestamps as Unix seconds
        Assert.Equal(createdPlusOneDay.ToUnixTimeSeconds(), loadedKeyRecord.Created.ToUnixTimeSeconds());
    }

    [Fact]
    public async Task TestLoadWithFailureShouldThrowException()
    {
        var brokenMetastore = CreateMetastoreWithBrokenDynamoClient();

        await Assert.ThrowsAsync<Exception>(
            () => brokenMetastore.TryLoadAsync(DynamoMetastoreHelper.ExistingTestKey, _created));
    }

    [Fact]
    public async Task TestLoadLatestWithFailureShouldThrowException()
    {
        var brokenMetastore = CreateMetastoreWithBrokenDynamoClient();

        await Assert.ThrowsAsync<Exception>(
            () => brokenMetastore.TryLoadLatestAsync(DynamoMetastoreHelper.ExistingTestKey));
    }

    [Fact]
    public void GetKeySuffixShouldReturnRegionEndpointName()
    {
        // Act
        var result = _dynamoDbMetastore.GetKeySuffix();

        // Assert
        Assert.Null(result);
    }

    [Theory]
    [InlineData(null, true)]   // null Revoked, with ParentKeyMeta
    [InlineData(false, true)]  // false Revoked, with ParentKeyMeta
    [InlineData(true, true)]   // true Revoked, with ParentKeyMeta
    [InlineData(null, false)]  // null Revoked, null ParentKeyMeta
    [InlineData(false, false)] // false Revoked, null ParentKeyMeta
    [InlineData(true, false)]  // true Revoked, null ParentKeyMeta
    public async Task TestStore(bool? revoked, bool hasParentKeyMeta)
    {
        // Arrange
        string testKeyId = "test_store_key";
        DateTimeOffset testCreated = DateTimeOffset.Now;
        KeyMeta parentKeyMeta = hasParentKeyMeta ? new KeyMeta("parent_key_id", DateTimeOffset.Now.AddDays(-1)) : null;

        var testKeyRecord = new KeyRecord(
            testCreated,
            "test_encrypted_key_data",
            revoked,
            parentKeyMeta
        );

        // Act
        bool storeResult = await _dynamoDbMetastore.StoreAsync(testKeyId, testCreated, testKeyRecord);

        // Assert
        Assert.True(storeResult);

        // Verify we can retrieve the stored record
        var (found, loadedKeyRecord) = await _dynamoDbMetastore.TryLoadAsync(testKeyId, testCreated);
        Assert.True(found);
        Assert.NotNull(loadedKeyRecord);
        Assert.Equal(testKeyRecord.Key, loadedKeyRecord.Key);
        Assert.Equal(testKeyRecord.Created.ToUnixTimeSeconds(), loadedKeyRecord.Created.ToUnixTimeSeconds());
        Assert.Equal(testKeyRecord.Revoked, loadedKeyRecord.Revoked);

        if (hasParentKeyMeta)
        {
            Assert.NotNull(loadedKeyRecord.ParentKeyMeta);
            Assert.Equal(testKeyRecord.ParentKeyMeta.Id, loadedKeyRecord.ParentKeyMeta.Id);
            Assert.Equal(testKeyRecord.ParentKeyMeta.Created.ToUnixTimeSeconds(), loadedKeyRecord.ParentKeyMeta.Created.ToUnixTimeSeconds());
        }
        else
        {
            Assert.Null(loadedKeyRecord.ParentKeyMeta);
        }

        // Verify the stored record can also be loaded by the old metastore implementation
        DynamoMetastoreHelper.VerifyKeyRecordUsingOldMetastore(_amazonDynamoDbClient, TestTableName, TestRegion, testKeyId, testKeyRecord);
    }

    [Fact]
    public async Task TestStoreWithDbErrorShouldThrowException()
    {
        // Arrange
        var brokenMetastore = CreateMetastoreWithBrokenDynamoClientForStore();
        string testKeyId = "test_store_key";
        DateTimeOffset testCreated = DateTimeOffset.Now;
        var testKeyRecord = new KeyRecord(testCreated, "test_encrypted_key_data", null, null);

        // Act & Assert
        await Assert.ThrowsAsync<Exception>(
            () => brokenMetastore.StoreAsync(testKeyId, testCreated, testKeyRecord));
    }

    [Fact]
    public async Task TestStoreWithDuplicateShouldReturnFalse()
    {
        // Arrange
        string testKeyId = "test_duplicate_key";
        DateTimeOffset testCreated = DateTimeOffset.Now;
        var testKeyRecord = new KeyRecord(testCreated, "test_encrypted_key_data", null, null);

        // Act
        bool firstAttempt = await _dynamoDbMetastore.StoreAsync(testKeyId, testCreated, testKeyRecord);
        bool secondAttempt = await _dynamoDbMetastore.StoreAsync(testKeyId, testCreated, testKeyRecord);

        // Assert
        Assert.True(firstAttempt);
        Assert.False(secondAttempt);
    }
}
