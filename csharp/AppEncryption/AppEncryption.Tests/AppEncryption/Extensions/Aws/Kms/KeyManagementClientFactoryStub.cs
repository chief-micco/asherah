using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Amazon.KeyManagementService;
using GoDaddy.Asherah.AppEncryption.Extensions.Aws.Kms;

namespace GoDaddy.Asherah.AppEncryption.Tests.AppEncryption.Extensions.Aws.Kms
{
    /// <summary>
    /// Stub implementation of IKeyManagementClientFactory for testing purposes.
    /// </summary>
    [ExcludeFromCodeCoverage]
    public class KeyManagementClientFactoryStub : IKeyManagementClientFactory
    {
        private readonly KeyManagementServiceOptions _options;
        private readonly Dictionary<string, AwsKeyManagementStub> _clients = new Dictionary<string, AwsKeyManagementStub>();

        /// <summary>
        /// Gets the dictionary of created clients by region.
        /// </summary>
        public IReadOnlyDictionary<string, AwsKeyManagementStub> Clients => _clients;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyManagementClientFactoryStub"/> class.
        /// </summary>
        /// <param name="options">The key management service options.</param>
        public KeyManagementClientFactoryStub(KeyManagementServiceOptions options)
        {
            _options = options;
        }

        /// <inheritdoc/>
        public IAmazonKeyManagementService CreateForRegion(string region)
        {
            if (_clients.TryGetValue(region, out var existingClient))
            {
                return existingClient;
            }

            var regionKeyArn = _options.RegionKeyArns.FirstOrDefault(rka => rka.Region.Equals(region, StringComparison.OrdinalIgnoreCase));
            if (regionKeyArn == null)
            {
                throw new InvalidOperationException($"No key ARN found for region: {region}");
            }

            var client = new AwsKeyManagementStub(regionKeyArn.KeyArn);
            _clients[region] = client;
            return client;
        }
    }
}
