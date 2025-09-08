using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace GoDaddy.Asherah.AppEncryption.Extensions.Aws.Kms
{
    /// <summary>
    /// Options for configuring the AWS Key Management Service.
    /// </summary>
    public class KeyManagementServiceOptions
    {
        /// <summary>
        /// Gets or sets the list of region and key ARN pairs for multi-region KMS support.
        /// </summary>
        [JsonPropertyName("RegionKeyArns")]
        public List<RegionKeyArn> RegionKeyArns { get; set; } = new List<RegionKeyArn>();
    }
}
