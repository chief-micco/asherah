namespace GoDaddy.Asherah.AppEncryption.Extensions.Aws.Metastore;

/// <summary>
/// Configuration options for DynamoDbMetastore.
/// </summary>
/// <param name="KeyRecordTableName">The name of the DynamoDB table to store key records.</param>
public record DynamoDbMetastoreOptions(string KeyRecordTableName);
