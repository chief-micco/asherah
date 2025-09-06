using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.DocumentModel;
using Amazon.DynamoDBv2.Model;
using Amazon.Runtime;
using GoDaddy.Asherah.AppEncryption.Persistence;
using GoDaddy.Asherah.AppEncryption.Tests.Fixtures;
using GoDaddy.Asherah.Crypto.Exceptions;
using LanguageExt;
using Microsoft.Extensions.Logging;
using Moq;
using Newtonsoft.Json.Linq;
using Xunit;

using static GoDaddy.Asherah.AppEncryption.Persistence.DynamoDbMetastoreImpl;

namespace GoDaddy.Asherah.AppEncryption.Tests.AppEncryption.Persistence
{
    public class DynamoDbMetastoreImplTest : IClassFixture<DynamoDBContainerFixture>, IClassFixture<MetricsFixture>, IDisposable
    {
        private const string DynamoDbPort = "8000";
        private const string Region = "us-west-2";
        private const string TestKeyWithRegionSuffix = DynamoMetastoreHelper.ExistingTestKey + "_" + Region;

        private readonly AmazonDynamoDBClient amazonDynamoDbClient;

        private readonly DynamoDbMetastoreImpl dynamoDbMetastoreImpl;
        private readonly DateTimeOffset created;
        private string serviceUrl;

        public DynamoDbMetastoreImplTest(DynamoDBContainerFixture dynamoDbContainerFixture)
        {
            serviceUrl = dynamoDbContainerFixture.GetServiceUrl();
            AmazonDynamoDBConfig clientConfig = new AmazonDynamoDBConfig
            {
                ServiceURL = serviceUrl,
                AuthenticationRegion = "us-west-2",
            };
            amazonDynamoDbClient = new AmazonDynamoDBClient(clientConfig);

            DynamoMetastoreHelper.CreateTableSchema(amazonDynamoDbClient, "EncryptionKey").Wait();

            dynamoDbMetastoreImpl = NewBuilder(Region)
                .WithEndPointConfiguration(serviceUrl, Region)
                .Build();

            // Pre-populate test data using helper and capture the created timestamp
            created = DynamoMetastoreHelper.PrePopulateTestDataUsingOldMetastore(amazonDynamoDbClient, "EncryptionKey", Region).Result;
        }

        public void Dispose()
        {
            try
            {
                DeleteTableResponse deleteTableResponse = amazonDynamoDbClient
                    .DeleteTableAsync(dynamoDbMetastoreImpl.TableName)
                    .Result;
            }
            catch (AggregateException)
            {
                // There is no such table.
            }
        }


        [Fact]
        public void TestLoadSuccess()
        {
            Option<JObject> actualJsonObject = dynamoDbMetastoreImpl.Load(DynamoMetastoreHelper.ExistingTestKey, created);

            Assert.True(actualJsonObject.IsSome);
            Assert.True(JToken.DeepEquals(JObject.FromObject(DynamoMetastoreHelper.ExistingKeyRecord), (JObject)actualJsonObject));
        }

        [Fact]
        public void TestLoadWithNoResultShouldReturnEmpty()
        {
            Option<JObject> actualJsonObject = dynamoDbMetastoreImpl.Load("fake_key", created);

            Assert.False(actualJsonObject.IsSome);
        }

        [Fact]
        public void TestLoadWithFailureShouldReturnEmpty()
        {
            Dispose();
            Option<JObject> actualJsonObject = dynamoDbMetastoreImpl.Load(DynamoMetastoreHelper.ExistingTestKey, created);

            Assert.False(actualJsonObject.IsSome);
        }

        [Fact]
        public void TestLoadLatestWithSingleRecord()
        {
            Option<JObject> actualJsonObject = dynamoDbMetastoreImpl.LoadLatest(DynamoMetastoreHelper.ExistingTestKey);

            Assert.True(actualJsonObject.IsSome);
            Assert.True(JToken.DeepEquals(JObject.FromObject(DynamoMetastoreHelper.ExistingKeyRecord), (JObject)actualJsonObject));
        }

        [Fact]
        public void TestLoadLatestWithSingleRecordAndSuffix()
        {
            DynamoDbMetastoreImpl dbMetastoreImpl = NewBuilder(Region)
                .WithEndPointConfiguration(serviceUrl, Region)
                .WithKeySuffix()
                .Build();

            Option<JObject> actualJsonObject = dbMetastoreImpl.LoadLatest(DynamoMetastoreHelper.ExistingTestKey);

            Assert.True(actualJsonObject.IsSome);
            Assert.True(JToken.DeepEquals(JObject.FromObject(DynamoMetastoreHelper.ExistingKeyRecord), (JObject)actualJsonObject));
        }

        [Fact]
        public async Task TestLoadLatestWithMultipleRecords()
        {
            // Create a local table instance for this test
            Table table = (Table)new TableBuilder(amazonDynamoDbClient, dynamoDbMetastoreImpl.TableName)
                .AddHashKey(PartitionKey, DynamoDBEntryType.String)
                .AddRangeKey(SortKey, DynamoDBEntryType.Numeric)
                .Build();

            DateTimeOffset createdMinusOneHour = created.AddHours(-1);
            DateTimeOffset createdPlusOneHour = created.AddHours(1);
            DateTimeOffset createdMinusOneDay = created.AddDays(-1);
            DateTimeOffset createdPlusOneDay = created.AddDays(1);

            // intentionally mixing up insertion order
            Document documentPlusOneHour = new Document
            {
                [PartitionKey] = DynamoMetastoreHelper.ExistingTestKey,
                [SortKey] = createdPlusOneHour.ToUnixTimeSeconds(),
                [AttributeKeyRecord] = Document.FromJson(new JObject
                {
                    { "mytime", createdPlusOneHour },
                }.ToString()),
            };
            await table.PutItemAsync(documentPlusOneHour, CancellationToken.None);

            Document documentPlusOneDay = new Document
            {
                [PartitionKey] = DynamoMetastoreHelper.ExistingTestKey,
                [SortKey] = createdPlusOneDay.ToUnixTimeSeconds(),
                [AttributeKeyRecord] = Document.FromJson(new JObject
                {
                    { "mytime", createdPlusOneDay },
                }.ToString()),
            };
            await table.PutItemAsync(documentPlusOneDay, CancellationToken.None);

            Document documentMinusOneHour = new Document
            {
                [PartitionKey] = DynamoMetastoreHelper.ExistingTestKey,
                [SortKey] = createdMinusOneHour.ToUnixTimeSeconds(),
                [AttributeKeyRecord] = Document.FromJson(new JObject
                {
                    { "mytime", createdMinusOneHour },
                }.ToString()),
            };
            await table.PutItemAsync(documentMinusOneHour, CancellationToken.None);

            Document documentMinusOneDay = new Document
            {
                [PartitionKey] = DynamoMetastoreHelper.ExistingTestKey,
                [SortKey] = createdMinusOneDay.ToUnixTimeSeconds(),
                [AttributeKeyRecord] = Document.FromJson(new JObject
                {
                    { "mytime", createdMinusOneDay },
                }.ToString()),
            };
            await table.PutItemAsync(documentMinusOneDay, CancellationToken.None);

            Option<JObject> actualJsonObject = dynamoDbMetastoreImpl.LoadLatest(DynamoMetastoreHelper.ExistingTestKey);

            Assert.True(actualJsonObject.IsSome);
            Assert.True(JToken.DeepEquals(createdPlusOneDay, ((JObject)actualJsonObject).GetValue("mytime")));
        }

        [Fact]
        public void TestLoadLatestWithNoResultShouldReturnEmpty()
        {
            Option<JObject> actualJsonObject = dynamoDbMetastoreImpl.LoadLatest("fake_key");

            Assert.False(actualJsonObject.IsSome);
        }

        [Fact]
        public void TestLoadLatestWithFailureShouldReturnEmpty()
        {
            Dispose();
            Option<JObject> actualJsonObject = dynamoDbMetastoreImpl.LoadLatest(DynamoMetastoreHelper.ExistingTestKey);

            Assert.False(actualJsonObject.IsSome);
        }

        [Fact]
        public void TestStore()
        {
            bool actualValue = dynamoDbMetastoreImpl.Store(DynamoMetastoreHelper.ExistingTestKey, DateTimeOffset.Now, JObject.FromObject(DynamoMetastoreHelper.ExistingKeyRecord));

            Assert.True(actualValue);
        }

        [Fact]
        public void TestStoreWithSuffixSuccess()
        {
            DynamoDbMetastoreImpl dbMetastoreImpl = NewBuilder(Region)
                .WithEndPointConfiguration(serviceUrl, Region)
                .WithKeySuffix()
                .Build();
            bool actualValue = dbMetastoreImpl.Store(DynamoMetastoreHelper.ExistingTestKey, DateTimeOffset.Now, JObject.FromObject(DynamoMetastoreHelper.ExistingKeyRecord));

            Assert.True(actualValue);
        }

        [Fact]
        public void TestStoreWithClientProvidedExternally()
        {
            var client = new AmazonDynamoDBClient(new AmazonDynamoDBConfig
            {
                ServiceURL = serviceUrl,
                AuthenticationRegion = Region,
            });

            var dbMetastoreImpl = NewBuilder(Region)
                .WithDynamoDbClient(client)
                .Build();
            bool actualValue = dbMetastoreImpl.Store(DynamoMetastoreHelper.ExistingTestKey, DateTimeOffset.Now, JObject.FromObject(DynamoMetastoreHelper.ExistingKeyRecord));

            Assert.True(actualValue);
        }

        [Fact]
        public void TestStoreWithDbErrorShouldThrowException()
        {
            Dispose();
            Assert.Throws<AppEncryptionException>(() =>
                dynamoDbMetastoreImpl.Store(DynamoMetastoreHelper.ExistingTestKey, DateTimeOffset.Now, JObject.FromObject(DynamoMetastoreHelper.ExistingKeyRecord)));
        }

        [Fact]
        public void TestStoreWithDuplicateShouldReturnFalse()
        {
            DateTimeOffset now = DateTimeOffset.Now;
            bool firstAttempt = dynamoDbMetastoreImpl.Store(DynamoMetastoreHelper.ExistingTestKey, now, JObject.FromObject(DynamoMetastoreHelper.ExistingKeyRecord));
            bool secondAttempt = dynamoDbMetastoreImpl.Store(DynamoMetastoreHelper.ExistingTestKey, now, JObject.FromObject(DynamoMetastoreHelper.ExistingKeyRecord));

            Assert.True(firstAttempt);
            Assert.False(secondAttempt);
        }

        [Fact]
        public void TestBuilderPathWithEndPointConfiguration()
        {
            DynamoDbMetastoreImpl dbMetastoreImpl = NewBuilder(Region)
                .WithEndPointConfiguration(serviceUrl, Region)
                .Build();

            Assert.NotNull(dbMetastoreImpl);
        }

        [Fact]
        public void TestBuilderPathWithRegion()
        {
            Mock<Builder> builder = new Mock<Builder>(Region);
            Table loadTable = (Table)new TableBuilder(amazonDynamoDbClient, "EncryptionKey")
                .AddHashKey(PartitionKey, DynamoDBEntryType.String)
                .AddRangeKey(SortKey, DynamoDBEntryType.Numeric)
                .Build();

            builder.Setup(x => x.LoadTable(It.IsAny<IAmazonDynamoDB>(), Region))
                .Returns(loadTable);

            DynamoDbMetastoreImpl dbMetastoreImpl = builder.Object
                .WithRegion(Region)
                .Build();

            Assert.NotNull(dbMetastoreImpl);
        }

        [Fact]
        public void TestBuilderPathWithKeySuffix()
        {
            DynamoDbMetastoreImpl dbMetastoreImpl = NewBuilder(Region)
                .WithEndPointConfiguration(serviceUrl, Region)
                .WithKeySuffix()
                .Build();

            Assert.NotNull(dbMetastoreImpl);
            Assert.Equal(Region, dbMetastoreImpl.GetKeySuffix());
        }

        [Fact]
        public void TestBuilderPathWithoutKeySuffix()
        {
            DynamoDbMetastoreImpl dbMetastoreImpl = NewBuilder(Region)
                .WithEndPointConfiguration(serviceUrl, Region)
                .Build();

            Assert.NotNull(dbMetastoreImpl);
            Assert.Equal(string.Empty, dbMetastoreImpl.GetKeySuffix());
        }

        [Fact]
        public void TestBuilderPathWithCredentials()
        {
            var dbMetastoreImpl = NewBuilder(Region)
                .WithEndPointConfiguration(serviceUrl, Region)
                .WithCredentials(new BasicAWSCredentials("dummykey", "dummy_secret"))
                .Build();

            Assert.NotNull(dbMetastoreImpl);
        }

        [Fact]
        public void TestBuilderPathWithInvalidCredentials()
        {
            var emptySecretKey = string.Empty;
            Assert.ThrowsAny<Exception>(() => NewBuilder(Region)
                .WithEndPointConfiguration(serviceUrl, Region)
                .WithCredentials(new BasicAWSCredentials("not-dummykey", emptySecretKey))
                .Build());
        }

        [Fact]
        public async Task TestBuilderPathWithTableName()
        {
            const string tempTableName = "DummyTable";

            // Use AWS SDK to create client
            AmazonDynamoDBConfig amazonDynamoDbConfig = new AmazonDynamoDBConfig
            {
                ServiceURL = serviceUrl,
                AuthenticationRegion = "us-west-2",
            };
            AmazonDynamoDBClient tempDynamoDbClient = new AmazonDynamoDBClient(amazonDynamoDbConfig);
            await DynamoMetastoreHelper.CreateTableSchema(tempDynamoDbClient, tempTableName);

            // Put the object in temp table
            Table tempTable = (Table)new TableBuilder(tempDynamoDbClient, tempTableName)
                .AddHashKey(PartitionKey, DynamoDBEntryType.String)
                .AddRangeKey(SortKey, DynamoDBEntryType.Numeric)
                .Build();
            JObject jObject = JObject.FromObject(DynamoMetastoreHelper.ExistingKeyRecord);
            Document document = new Document
            {
                [PartitionKey] = DynamoMetastoreHelper.ExistingTestKey,
                [SortKey] = created.ToUnixTimeSeconds(),
                [AttributeKeyRecord] = Document.FromJson(jObject.ToString()),
            };
            await tempTable.PutItemAsync(document, CancellationToken.None);

            // Create a metastore object using the withTableName step
            DynamoDbMetastoreImpl dbMetastoreImpl = NewBuilder(Region)
                .WithEndPointConfiguration(serviceUrl, "us-west-2")
                .WithTableName(tempTableName)
                .Build();
            Option<JObject> actualJsonObject = dbMetastoreImpl.Load(DynamoMetastoreHelper.ExistingTestKey, created);

            // Verify that we were able to load and successfully decrypt the item from the metastore object created withTableName
            Assert.True(actualJsonObject.IsSome);
            Assert.True(JToken.DeepEquals(JObject.FromObject(DynamoMetastoreHelper.ExistingKeyRecord), (JObject)actualJsonObject));
        }

        [Fact]
        public void TestPrimaryBuilderPath()
        {
            Mock<Builder> builder = new Mock<Builder>(Region);
            Table loadTable = (Table)new TableBuilder(amazonDynamoDbClient, "EncryptionKey")
                .AddHashKey(PartitionKey, DynamoDBEntryType.String)
                .AddRangeKey(SortKey, DynamoDBEntryType.Numeric)
                .Build();

            builder.Setup(x => x.LoadTable(It.IsAny<IAmazonDynamoDB>(), Region))
                .Returns(loadTable);

            DynamoDbMetastoreImpl dbMetastoreImpl = builder.Object
                .Build();

            Assert.NotNull(dbMetastoreImpl);
        }

        [Fact]
        public void TestBuilderPathWithLoggerEnabled()
        {
            var mockLogger = new Mock<ILogger>();

            var dbMetastoreImpl = NewBuilder(Region)
                .WithEndPointConfiguration(serviceUrl, Region)
                .WithLogger(mockLogger.Object)
                .Build();

            Assert.NotNull(dbMetastoreImpl);
        }

        [Fact]
        public void TestBuilderPathWithLoggerDisabled()
        {
            var dbMetastoreImpl = NewBuilder(Region)
                .WithEndPointConfiguration(serviceUrl, Region)
                .Build();

            Assert.NotNull(dbMetastoreImpl);
        }

        [Fact]
        public void TestBuilderPathWithLoggerAndCredentials()
        {
            var mockLogger = new Mock<ILogger>();

            var dbMetastoreImpl = NewBuilder(Region)
                .WithEndPointConfiguration(serviceUrl, Region)
                .WithLogger(mockLogger.Object)
                .WithCredentials(new BasicAWSCredentials("dummykey", "dummy_secret"))
                .Build();

            Assert.NotNull(dbMetastoreImpl);
        }

        [Fact]
        public void TestWithLoggerReturnsCorrectInterface()
        {
            var mockLogger = new Mock<ILogger>();

            var buildStep = NewBuilder(Region)
                .WithEndPointConfiguration(serviceUrl, Region)
                .WithLogger(mockLogger.Object);

            Assert.IsAssignableFrom<IBuildStep>(buildStep);
        }
    }
}
