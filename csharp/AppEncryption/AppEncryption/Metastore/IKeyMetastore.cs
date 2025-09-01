using System;
using GoDaddy.Asherah.AppEncryption.Models;

namespace GoDaddy.Asherah.AppEncryption.Metastore
{
    /// <summary>
    /// The KeyMetastore interface provides methods that can be used to load and store system and intermediate keys from a
    /// supported database using key records.
    /// </summary>
    public interface IKeyMetastore
    {
        /// <summary>
        /// Attempts to load the key record associated with the keyId and created time.
        /// </summary>
        ///
        /// <param name="keyId">The keyId to lookup.</param>
        /// <param name="created">The created time to lookup.</param>
        /// <param name="keyRecord">The key record if found.</param>
        /// <returns>True if the key record was found, false otherwise.</returns>
        bool TryLoad(string keyId, DateTimeOffset created, out KeyRecord keyRecord);

        /// <summary>
        /// Attempts to load the latest key record associated with the keyId.
        /// </summary>
        ///
        /// <param name="keyId">The keyId to lookup.</param>
        /// <param name="keyRecord">The latest key record if found.</param>
        /// <returns>True if a key record was found, false otherwise.</returns>
        bool TryLoadLatest(string keyId, out KeyRecord keyRecord);

        /// <summary>
        /// Stores the key record using the specified keyId and created time.
        /// </summary>
        ///
        /// <param name="keyId">The keyId to store.</param>
        /// <param name="created">The created time to store.</param>
        /// <param name="keyRecord">The key record to store.</param>
        /// <returns>True if the store succeeded, false if the store failed for a known condition e.g., trying to save
        /// a duplicate value should return false, not throw an exception.</returns>
        bool Store(string keyId, DateTimeOffset created, KeyRecord keyRecord);

        /// <summary>
        /// Returns the key suffix or "" if key suffix option is disabled.
        /// </summary>
        ///
        /// <returns>
        /// The key suffix.
        /// </returns>
        string GetKeySuffix();
    }
}
