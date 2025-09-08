using System;
using Amazon.KeyManagementService;
using Amazon.Runtime;

namespace GoDaddy.Asherah.AppEncryption.Extensions.Aws.Kms
{
    /// <summary>
    /// Simple implementation of <see cref="IKeyManagementClientFactory"/> that creates KMS clients
    /// for any region using provided AWS credentials.
    /// </summary>
    public class KeyManagementClientFactory : IKeyManagementClientFactory
    {
        private readonly AWSCredentials _credentials;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyManagementClientFactory"/> class.
        /// </summary>
        /// <param name="credentials">The AWS credentials to use for authentication.</param>
        public KeyManagementClientFactory(AWSCredentials credentials)
        {
            _credentials = credentials;
        }

        /// <inheritdoc/>
        public IAmazonKeyManagementService CreateForRegion(string region)
        {
            if (string.IsNullOrWhiteSpace(region))
            {
                throw new ArgumentException("Region cannot be null or empty", nameof(region));
            }

            var regionEndpoint = Amazon.RegionEndpoint.GetBySystemName(region);
            if (regionEndpoint == null)
            {
                throw new ArgumentException($"Invalid AWS region: {region}", nameof(region));
            }

            var config = new AmazonKeyManagementServiceConfig
            {
                RegionEndpoint = regionEndpoint
            };

            return new AmazonKeyManagementServiceClient(_credentials, config);
        }
    }
}
