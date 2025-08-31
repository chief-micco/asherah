using System;
using GoDaddy.Asherah.AppEncryption.Models;
using LanguageExt;
using Newtonsoft.Json.Linq;

namespace GoDaddy.Asherah.AppEncryption.Persistence
{
    /// <summary>
    /// Adapter that wraps DynamoDbMetastoreImpl to work with the new IKeyMetastore interface.
    /// Converts between KeyRecord and JObject for storage.
    /// </summary>
    public class DynamoDbKeyMetastoreAdapter : IKeyMetastore
    {
        private readonly DynamoDbMetastoreImpl _dynamoDbMetastore;

        /// <summary>
        /// Initializes a new instance of the <see cref="DynamoDbKeyMetastoreAdapter"/> class.
        /// </summary>
        ///
        /// <param name="dynamoDbMetastore">The DynamoDB metastore implementation to wrap.</param>
        public DynamoDbKeyMetastoreAdapter(DynamoDbMetastoreImpl dynamoDbMetastore)
        {
            _dynamoDbMetastore = dynamoDbMetastore ?? throw new ArgumentNullException(nameof(dynamoDbMetastore));
        }

        /// <inheritdoc/>
        public bool TryLoad(string keyId, DateTimeOffset created, out KeyRecord keyRecord)
        {
            var option = _dynamoDbMetastore.Load(keyId, created);
            if (option.IsSome)
            {
                keyRecord = ConvertFromJObject((JObject)option);
                return true;
            }

            keyRecord = null;
            return false;
        }

        /// <inheritdoc/>
        public bool TryLoadLatest(string keyId, out KeyRecord keyRecord)
        {
            var option = _dynamoDbMetastore.LoadLatest(keyId);
            if (option.IsSome)
            {
                keyRecord = ConvertFromJObject((JObject)option);
                return true;
            }

            keyRecord = null;
            return false;
        }

        /// <inheritdoc/>
        public bool Store(string keyId, DateTimeOffset created, KeyRecord keyRecord)
        {
            var jObject = ConvertToJObject(keyRecord);
            return _dynamoDbMetastore.Store(keyId, created, jObject);
        }

        /// <inheritdoc/>
        public string GetKeySuffix()
        {
            return _dynamoDbMetastore.GetKeySuffix();
        }

        private static KeyRecord ConvertFromJObject(JObject jObject)
        {
            // Convert JObject back to KeyRecord
            // This would need to handle the JSON structure of the existing EnvelopeKeyRecord format
            // and convert it to our new KeyRecord model
            throw new NotImplementedException("Conversion from JObject to KeyRecord not yet implemented");
        }

        private static JObject ConvertToJObject(KeyRecord keyRecord)
        {
            // Convert KeyRecord to JObject
            // This would need to create the JSON structure expected by the existing DynamoDbMetastoreImpl
            throw new NotImplementedException("Conversion from KeyRecord to JObject not yet implemented");
        }
    }
}
