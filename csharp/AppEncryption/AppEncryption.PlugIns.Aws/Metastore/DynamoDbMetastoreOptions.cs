namespace GoDaddy.Asherah.AppEncryption.PlugIns.Aws.Metastore
{
    /// <summary>
    /// Configuration options for DynamoDbMetastore.
    /// </summary>
    public class DynamoDbMetastoreOptions
    {
        /// <summary>
        /// The table name for the KeyRecord storage
        /// </summary>
        public string KeyRecordTableName { get; set; } = "KeyRecord";
    };
}
