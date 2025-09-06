using System;
using System.Threading.Tasks;
using GoDaddy.Asherah.AppEncryption.Metastore;
using Xunit;

namespace GoDaddy.Asherah.AppEncryption.Tests.AppEncryption.Metastore
{
    public class InMemoryKeyMetastoreImplTest : IDisposable
    {
        private readonly InMemoryKeyMetastoreImpl inMemoryKeyMetastoreImpl;

        public InMemoryKeyMetastoreImplTest()
        {
            inMemoryKeyMetastoreImpl = new InMemoryKeyMetastoreImpl();
        }

        [Fact]
        private async Task TestTryLoadAndStoreWithValidKey()
        {
            const string keyId = "ThisIsMyKey";
            DateTimeOffset created = DateTimeOffset.UtcNow;
            var keyRecord = new KeyRecord(created, "test-key-data", false);

            await inMemoryKeyMetastoreImpl.StoreAsync(keyId, created, keyRecord);

            var (success, actualKeyRecord) = await inMemoryKeyMetastoreImpl.TryLoadAsync(keyId, created);

            Assert.True(success);
            Assert.Equal(keyRecord, actualKeyRecord);
        }

        [Fact]
        private async Task TestTryLoadAndStoreWithInvalidKey()
        {
            const string keyId = "ThisIsMyKey";
            DateTimeOffset created = DateTimeOffset.UtcNow;
            var keyRecord = new KeyRecord(created, "test-key-data", false);

            await inMemoryKeyMetastoreImpl.StoreAsync(keyId, created, keyRecord);

            var (success, actualKeyRecord) = await inMemoryKeyMetastoreImpl.TryLoadAsync("some non-existent key", created);

            Assert.False(success);
            Assert.Null(actualKeyRecord);
        }

        [Fact]
        private async Task TestTryLoadLatestMultipleCreatedAndValuesForKeyIdShouldReturnLatest()
        {
            const string keyId = "ThisIsMyKey";
            DateTimeOffset created = DateTimeOffset.UtcNow;
            var keyRecord = new KeyRecord(created, "test-key-data", false);

            await inMemoryKeyMetastoreImpl.StoreAsync(keyId, created, keyRecord);

            DateTimeOffset createdOneHourLater = created.AddHours(1);
            var keyRecordOneHourLater = new KeyRecord(createdOneHourLater, "test-key-data-hour", false);
            await inMemoryKeyMetastoreImpl.StoreAsync(keyId, createdOneHourLater, keyRecordOneHourLater);

            DateTimeOffset createdOneDayLater = created.AddDays(1);
            var keyRecordOneDayLater = new KeyRecord(createdOneDayLater, "test-key-data-day", false);
            await inMemoryKeyMetastoreImpl.StoreAsync(keyId, createdOneDayLater, keyRecordOneDayLater);

            DateTimeOffset createdOneWeekEarlier = created.AddDays(-7);
            var keyRecordOneWeekEarlier = new KeyRecord(createdOneWeekEarlier, "test-key-data-week", false);
            await inMemoryKeyMetastoreImpl.StoreAsync(keyId, createdOneWeekEarlier, keyRecordOneWeekEarlier);

            var (success, actualKeyRecord) = await inMemoryKeyMetastoreImpl.TryLoadLatestAsync(keyId);

            Assert.True(success);
            Assert.Equal(keyRecordOneDayLater, actualKeyRecord);
        }

        [Fact]
        private async Task TestTryLoadLatestNonExistentKeyIdShouldReturnFalse()
        {
            const string keyId = "ThisIsMyKey";
            DateTimeOffset created = DateTimeOffset.UtcNow;
            var keyRecord = new KeyRecord(created, "test-key-data", false);

            await inMemoryKeyMetastoreImpl.StoreAsync(keyId, created, keyRecord);

            var (success, actualKeyRecord) = await inMemoryKeyMetastoreImpl.TryLoadLatestAsync("some non-existent key");

            Assert.False(success);
            Assert.Null(actualKeyRecord);
        }

        [Fact]
        private async Task TestStoreWithDuplicateKeyShouldReturnFalse()
        {
            const string keyId = "ThisIsMyKey";
            DateTimeOffset created = DateTimeOffset.UtcNow;
            var keyRecord = new KeyRecord(created, "test-key-data", false);

            Assert.True(await inMemoryKeyMetastoreImpl.StoreAsync(keyId, created, keyRecord));
            Assert.False(await inMemoryKeyMetastoreImpl.StoreAsync(keyId, created, keyRecord));
        }

        [Fact]
        private async Task TestStoreWithIntermediateKeyRecord()
        {
            const string keyId = "ThisIsMyKey";
            DateTimeOffset created = DateTimeOffset.UtcNow;
            var parentKeyMeta = new KeyMeta("parentKey", created.AddDays(-1));
            var keyRecord = new KeyRecord(created, "test-key-data-parent", false, parentKeyMeta);

            bool success = await inMemoryKeyMetastoreImpl.StoreAsync(keyId, created, keyRecord);

            Assert.True(success);

            var (loadSuccess, actualKeyRecord) = await inMemoryKeyMetastoreImpl.TryLoadAsync(keyId, created);
            Assert.True(loadSuccess);
            Assert.Equal(keyRecord, actualKeyRecord);
        }

        [Fact]
        private void TestGetKeySuffixReturnsEmptyString()
        {
            string keySuffix = inMemoryKeyMetastoreImpl.GetKeySuffix();
            Assert.Equal(string.Empty, keySuffix);
        }

        /// <summary>
        /// Disposes of the managed resources.
        /// </summary>
        public void Dispose()
        {
            inMemoryKeyMetastoreImpl?.Dispose();
        }
    }
}
