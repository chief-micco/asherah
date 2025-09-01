using System;
using GoDaddy.Asherah.AppEncryption.Models;
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
        private void TestTryLoadAndStoreWithValidKey()
        {
            const string keyId = "ThisIsMyKey";
            DateTimeOffset created = DateTimeOffset.UtcNow;
            var keyRecord = KeyRecord.NewSystemKeyRecord(created, new byte[] { 1, 2, 3 }, false);

            inMemoryKeyMetastoreImpl.Store(keyId, created, keyRecord);

            bool success = inMemoryKeyMetastoreImpl.TryLoad(keyId, created, out KeyRecord actualKeyRecord);

            Assert.True(success);
            Assert.Equal(keyRecord, actualKeyRecord);
        }

        [Fact]
        private void TestTryLoadAndStoreWithInvalidKey()
        {
            const string keyId = "ThisIsMyKey";
            DateTimeOffset created = DateTimeOffset.UtcNow;
            var keyRecord = KeyRecord.NewSystemKeyRecord(created, new byte[] { 1, 2, 3 }, false);

            inMemoryKeyMetastoreImpl.Store(keyId, created, keyRecord);

            bool success = inMemoryKeyMetastoreImpl.TryLoad("some non-existent key", created, out KeyRecord actualKeyRecord);

            Assert.False(success);
            Assert.Null(actualKeyRecord);
        }

        [Fact]
        private void TestTryLoadLatestMultipleCreatedAndValuesForKeyIdShouldReturnLatest()
        {
            const string keyId = "ThisIsMyKey";
            DateTimeOffset created = DateTimeOffset.UtcNow;
            var keyRecord = KeyRecord.NewSystemKeyRecord(created, new byte[] { 1, 2, 3 }, false);

            inMemoryKeyMetastoreImpl.Store(keyId, created, keyRecord);

            DateTimeOffset createdOneHourLater = created.AddHours(1);
            var keyRecordOneHourLater = KeyRecord.NewSystemKeyRecord(createdOneHourLater, new byte[] { 4, 5, 6 }, false);
            inMemoryKeyMetastoreImpl.Store(keyId, createdOneHourLater, keyRecordOneHourLater);

            DateTimeOffset createdOneDayLater = created.AddDays(1);
            var keyRecordOneDayLater = KeyRecord.NewSystemKeyRecord(createdOneDayLater, new byte[] { 7, 8, 9 }, false);
            inMemoryKeyMetastoreImpl.Store(keyId, createdOneDayLater, keyRecordOneDayLater);

            DateTimeOffset createdOneWeekEarlier = created.AddDays(-7);
            var keyRecordOneWeekEarlier = KeyRecord.NewSystemKeyRecord(createdOneWeekEarlier, new byte[] { 10, 11, 12 }, false);
            inMemoryKeyMetastoreImpl.Store(keyId, createdOneWeekEarlier, keyRecordOneWeekEarlier);

            bool success = inMemoryKeyMetastoreImpl.TryLoadLatest(keyId, out KeyRecord actualKeyRecord);

            Assert.True(success);
            Assert.Equal(keyRecordOneDayLater, actualKeyRecord);
        }

        [Fact]
        private void TestTryLoadLatestNonExistentKeyIdShouldReturnFalse()
        {
            const string keyId = "ThisIsMyKey";
            DateTimeOffset created = DateTimeOffset.UtcNow;
            var keyRecord = KeyRecord.NewSystemKeyRecord(created, new byte[] { 1, 2, 3 }, false);

            inMemoryKeyMetastoreImpl.Store(keyId, created, keyRecord);

            bool success = inMemoryKeyMetastoreImpl.TryLoadLatest("some non-existent key", out KeyRecord actualKeyRecord);

            Assert.False(success);
            Assert.Null(actualKeyRecord);
        }

        [Fact]
        private void TestStoreWithDuplicateKeyShouldReturnFalse()
        {
            const string keyId = "ThisIsMyKey";
            DateTimeOffset created = DateTimeOffset.UtcNow;
            var keyRecord = KeyRecord.NewSystemKeyRecord(created, new byte[] { 1, 2, 3 }, false);

            Assert.True(inMemoryKeyMetastoreImpl.Store(keyId, created, keyRecord));
            Assert.False(inMemoryKeyMetastoreImpl.Store(keyId, created, keyRecord));
        }

        [Fact]
        private void TestStoreWithIntermediateKeyRecord()
        {
            const string keyId = "ThisIsMyKey";
            DateTimeOffset created = DateTimeOffset.UtcNow;
            var parentKeyMeta = new KeyMeta("parentKey", created.AddDays(-1));
            var keyRecord = KeyRecord.NewIntermediateKeyRecord(created, new byte[] { 1, 2, 3 }, false, parentKeyMeta);

            bool success = inMemoryKeyMetastoreImpl.Store(keyId, created, keyRecord);

            Assert.True(success);

            bool loadSuccess = inMemoryKeyMetastoreImpl.TryLoad(keyId, created, out KeyRecord actualKeyRecord);
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
