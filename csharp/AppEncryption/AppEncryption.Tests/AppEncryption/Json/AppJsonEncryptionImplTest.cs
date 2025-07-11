using System;
using System.Collections.Generic;
using System.Text.Json.Nodes;
using GoDaddy.Asherah.AppEncryption.Envelope;
using GoDaddy.Asherah.AppEncryption.Kms;
using GoDaddy.Asherah.AppEncryption.Persistence;
using GoDaddy.Asherah.AppEncryption.Tests.AppEncryption.TestHelpers.Dummy;
using GoDaddy.Asherah.Crypto;
using GoDaddy.Asherah.Crypto.Engine.BouncyCastle;
using GoDaddy.Asherah.Crypto.Envelope;
using GoDaddy.Asherah.Crypto.Keys;
using LanguageExt;
using Xunit;

namespace GoDaddy.Asherah.AppEncryption.Tests.AppEncryption.Json
{
    [Collection("Logger Fixture collection")]
    public class AppJsonEncryptionImplTest : IClassFixture<MetricsFixture>
    {
        private readonly IMetastore<JsonObject> metastore;
        private readonly Persistence<JsonObject> dataPersistence;
        private readonly Partition partition;
        private readonly KeyManagementService keyManagementService;

        public AppJsonEncryptionImplTest()
        {
            partition = new DefaultPartition("PARTITION", "SYSTEM", "PRODUCT");
            Dictionary<string, JsonObject> memoryPersistence = new Dictionary<string, JsonObject>();

            dataPersistence = new AdhocPersistence<JsonObject>(
                key => memoryPersistence.TryGetValue(key, out JsonObject result) ? result : Option<JsonObject>.None,
                (key, jsonObject) => memoryPersistence.Add(key, jsonObject));

            metastore = new InMemoryMetastoreImpl<JsonObject>();
            keyManagementService = new DummyKeyManagementService();

            AeadEnvelopeCrypto aeadEnvelopeCrypto = new BouncyAes256GcmCrypto();

            // Generate a dummy systemKey document
            CryptoKey systemKey = aeadEnvelopeCrypto.GenerateKey();
            byte[] encryptedSystemKey = keyManagementService.EncryptKey(systemKey);

            EnvelopeKeyRecord systemKeyRecord = new EnvelopeKeyRecord(DateTimeOffset.UtcNow, null, encryptedSystemKey);

            // Write out the dummy systemKey record
            memoryPersistence.TryAdd(partition.SystemKeyId, systemKeyRecord.ToJson());
        }

        [Theory]
        [InlineData("GoDaddy")]
        [InlineData("ᐊᓕᒍᖅ ᓂᕆᔭᕌᖓᒃᑯ ᓱᕋᙱᑦᑐᓐᓇᖅᑐᖓ ")]
        [InlineData(
            "𠜎 𠜱 𠝹 𠱓 𠱸 𠲖 𠳏 𠳕 𠴕 𠵼 𠵿 𠸎 𠸏 𠹷 𠺝 𠺢 𠻗 𠻹 𠻺 𠼭 𠼮 𠽌 𠾴 𠾼 𠿪 𡁜 𡁯 𡁵 𡁶 𡁻 𡃁 𡃉 𡇙 𢃇 𢞵 𢫕 𢭃 𢯊 𢱑 𢱕 𢳂 𢴈 𢵌 𢵧 𢺳 𣲷 𤓓 𤶸 𤷪 𥄫 𦉘 𦟌 𦧲 𦧺 𧨾 𨅝 𨈇 𨋢 𨳊 𨳍 𨳒 𩶘")]
        public void TestRoundTrip(string testData)
        {
            RoundTripGeneric(testData, new BouncyAes256GcmCrypto());
        }

        private void RoundTripGeneric(string testData, AeadEnvelopeCrypto aeadEnvelopeCrypto)
        {
            CryptoPolicy cryptoPolicy = new DummyCryptoPolicy();
            using (SecureCryptoKeyDictionary<DateTimeOffset> secureCryptoKeyDictionary =
                new SecureCryptoKeyDictionary<DateTimeOffset>(cryptoPolicy.GetRevokeCheckPeriodMillis()))
            {
                IEnvelopeEncryption<JsonObject> envelopeEncryptionJsonImpl = new EnvelopeEncryptionJsonImpl(
                    partition,
                    metastore,
                    secureCryptoKeyDictionary,
                    new SecureCryptoKeyDictionary<DateTimeOffset>(cryptoPolicy.GetRevokeCheckPeriodMillis()),
                    aeadEnvelopeCrypto,
                    cryptoPolicy,
                    keyManagementService);
                using (Session<JsonObject, JsonObject> sessionJsonImpl =
                    new SessionJsonImpl<JsonObject>(envelopeEncryptionJsonImpl))
                {
                    Asherah.AppEncryption.Util.Json testJson = new Asherah.AppEncryption.Util.Json();
                    testJson.Put("Test", testData);

                    string persistenceKey = sessionJsonImpl.Store(testJson.ToJObject(), dataPersistence);

                    Option<JsonObject> testJson2 = sessionJsonImpl.Load(persistenceKey, dataPersistence);
                    Assert.True(testJson2.IsSome);
                    string resultData = ((JsonObject)testJson2)["Test"].GetValue<string>();

                    Assert.Equal(testData, resultData);
                }
            }
        }
    }
}
