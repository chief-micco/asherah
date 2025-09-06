using System;
using System.Collections.Generic;
using System.Globalization;
using System.Threading.Tasks;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.Model;
using GoDaddy.Asherah.AppEncryption.Metastore;
using GoDaddy.Asherah.Crypto.Exceptions;

namespace GoDaddy.Asherah.AppEncryption.Extensions.Aws.Metastore;

/// <summary>
/// Provides an AWS DynamoDB based implementation of <see cref="IKeyMetastore"/> to store and retrieve system keys
/// and intermediate keys as <see cref="KeyRecord"/> values.
/// </summary>
/// <param name="dynamoDbClient">The AWS DynamoDB client to use for operations.</param>
/// <param name="options">Configuration options for the metastore.</param>
public class DynamoDbMetastore(IAmazonDynamoDB dynamoDbClient, DynamoDbMetastoreOptions options) : IKeyMetastore
{
    internal const string PartitionKey = "Id";
    internal const string SortKey = "Created";
    internal const string AttributeKeyRecord = "KeyRecord";

    /// <inheritdoc />
    public async Task<(bool found, KeyRecord keyRecord)> TryLoadAsync(string keyId, DateTimeOffset created)
    {
        var request = new GetItemRequest
        {
            TableName = options.KeyRecordTableName,
            Key = new Dictionary<string, AttributeValue>
            {
                [PartitionKey] = new AttributeValue { S = keyId },
                [SortKey] = new AttributeValue { N = created.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture) }
            },
            ProjectionExpression = AttributeKeyRecord,
            ConsistentRead = true
        };

        var response = await dynamoDbClient.GetItemAsync(request);

        if (response.Item != null && response.Item.TryGetValue(AttributeKeyRecord, out var keyRecordAttribute))
        {
            var keyRecord = ConvertAttributeValueToKeyRecord(keyRecordAttribute);
            return (true, keyRecord);
        }

        return (false, null);
    }

    /// <inheritdoc />
    public async Task<(bool found, KeyRecord keyRecord)> TryLoadLatestAsync(string keyId)
    {
        var request = new QueryRequest
        {
            TableName = options.KeyRecordTableName,
            KeyConditionExpression = $"{PartitionKey} = :keyId",
            ExpressionAttributeValues = new Dictionary<string, AttributeValue>
            {
                [":keyId"] = new AttributeValue { S = keyId }
            },
            ProjectionExpression = AttributeKeyRecord,
            ScanIndexForward = false, // Sort descending (latest first)
            Limit = 1, // Only get the latest item
            ConsistentRead = true
        };

        var response = await dynamoDbClient.QueryAsync(request);

        if (response.Items != null && response.Items.Count > 0)
        {
            var item = response.Items[0];
            if (item.TryGetValue(AttributeKeyRecord, out var keyRecordAttribute))
            {
                var keyRecord = ConvertAttributeValueToKeyRecord(keyRecordAttribute);
                return (true, keyRecord);
            }
        }

        return (false, null);
    }

    /// <inheritdoc />
    public async Task<bool> StoreAsync(string keyId, DateTimeOffset created, KeyRecord keyRecord)
    {
        try
        {
            var keyRecordMap = new Dictionary<string, AttributeValue>
            {
                ["Key"] = new AttributeValue { S = keyRecord.Key },
                ["Created"] = new AttributeValue { N = keyRecord.Created.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture) }
            };

            // Only add Revoked if it has a value
            if (keyRecord.Revoked.HasValue)
            {
                keyRecordMap["Revoked"] = new AttributeValue { BOOL = keyRecord.Revoked.Value };
            }

            // Only add ParentKeyMeta if it exists
            if (keyRecord.ParentKeyMeta != null)
            {
                keyRecordMap["ParentKeyMeta"] = new AttributeValue
                {
                    M = new Dictionary<string, AttributeValue>
                    {
                        ["KeyId"] = new AttributeValue { S = keyRecord.ParentKeyMeta.Id },
                        ["Created"] = new AttributeValue { N = keyRecord.ParentKeyMeta.Created.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture) }
                    }
                };
            }

            var keyRecordAttribute = new AttributeValue { M = keyRecordMap };

            var item = new Dictionary<string, AttributeValue>
            {
                [PartitionKey] = new AttributeValue { S = keyId },
                [SortKey] = new AttributeValue { N = created.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture) },
                [AttributeKeyRecord] = keyRecordAttribute
            };

            var request = new PutItemRequest
            {
                TableName = options.KeyRecordTableName,
                Item = item,
                ConditionExpression = $"attribute_not_exists({PartitionKey})"
            };

            await dynamoDbClient.PutItemAsync(request);
            return true;
        }
        catch (ConditionalCheckFailedException)
        {
            return false;
        }
    }

    /// <inheritdoc />
    public string GetKeySuffix()
    {
        return dynamoDbClient.Config.RegionEndpoint?.SystemName;
    }

    private static KeyRecord ConvertAttributeValueToKeyRecord(AttributeValue keyRecordAttribute)
    {
        if (keyRecordAttribute.M == null)
        {
            throw new ArgumentException("KeyRecord attribute must be a Map", nameof(keyRecordAttribute));
        }

        var map = keyRecordAttribute.M;

        if (!map.TryGetValue("Key", out var keyAttr) || keyAttr.S == null)
        {
            throw new ArgumentException("KeyRecord must contain Key field", nameof(keyRecordAttribute));
        }
        var keyString = keyAttr.S;

        // Extract Created (Unix timestamp)
        if (!map.TryGetValue("Created", out var createdAttr) || createdAttr.N == null)
        {
            throw new ArgumentException("KeyRecord must contain Created field", nameof(keyRecordAttribute));
        }
        var created = DateTimeOffset.FromUnixTimeSeconds(long.Parse(createdAttr.N, CultureInfo.InvariantCulture));

        // Extract Revoked (optional boolean)
        bool? revoked = null;
        if (map.TryGetValue("Revoked", out var revokedAttr) && revokedAttr.BOOL.HasValue)
        {
            revoked = revokedAttr.BOOL.Value;
        }

        // Extract ParentKeyMeta (optional map)
        KeyMeta parentKeyMeta = null;
        if (map.TryGetValue("ParentKeyMeta", out var parentMetaAttr) && parentMetaAttr.M != null)
        {
            var parentMetaMap = parentMetaAttr.M;
            if (parentMetaMap.TryGetValue("KeyId", out var parentKeyIdAttr) && parentMetaMap.TryGetValue("Created", out var parentCreatedAttr))
            {
                var parentKeyId = parentKeyIdAttr.S;
                var parentCreated = DateTimeOffset.FromUnixTimeSeconds(long.Parse(parentCreatedAttr.N, CultureInfo.InvariantCulture));
                parentKeyMeta = new KeyMeta(parentKeyId, parentCreated);
            }
        }

        return new KeyRecord(created, keyString, revoked, parentKeyMeta);
    }
}
