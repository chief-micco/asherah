using System;

namespace GoDaddy.Asherah.AppEncryption.Models
{
    /// <summary>
    /// Represents a key record with basic properties for encrypted keys.
    /// System KeyRecords will not have a ParentKeyMeta, while Intermediate KeyRecords will have a ParentKeyMeta.
    /// </summary>
    public class KeyRecord
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyRecord"/> class.
        /// </summary>
        ///
        /// <param name="created">Creation time of the encrypted key.</param>
        /// <param name="encryptedKey">The encrypted key bytes.</param>
        /// <param name="revoked">The revocation status of the encrypted key.</param>
        /// <param name="parentKeyMeta">The metadata for the parent key, if any.</param>
        private KeyRecord(DateTimeOffset created, byte[] encryptedKey, bool? revoked, KeyMeta parentKeyMeta = null)
        {
            Created = created;
            EncryptedKey = encryptedKey ?? throw new ArgumentNullException(nameof(encryptedKey));
            Revoked = revoked;
            ParentKeyMeta = parentKeyMeta;
        }

        /// <summary>
        /// Gets the creation time of the encrypted key.
        /// </summary>
        public DateTimeOffset Created { get; }

        /// <summary>
        /// Gets the encrypted key bytes.
        /// </summary>
        public byte[] EncryptedKey { get; }

        /// <summary>
        /// Gets the revocation status of the encrypted key.
        /// </summary>
        public bool? Revoked { get; }

        /// <summary>
        /// Gets the metadata for the parent key, if any.
        /// </summary>
        public KeyMeta ParentKeyMeta { get; }

        /// <summary>
        /// Creates a system key record with no parent key metadata.
        /// </summary>
        ///
        /// <param name="created">Creation time of the encrypted key.</param>
        /// <param name="encryptedKey">The encrypted key bytes.</param>
        /// <param name="revoked">The revocation status of the encrypted key.</param>
        /// <returns>A new system key record.</returns>
        public static KeyRecord NewSystemKeyRecord(DateTimeOffset created, byte[] encryptedKey, bool? revoked)
        {
            return new KeyRecord(created, encryptedKey, revoked, null);
        }

        /// <summary>
        /// Creates an intermediate key record with parent key metadata.
        /// </summary>
        ///
        /// <param name="created">Creation time of the encrypted key.</param>
        /// <param name="encryptedKey">The encrypted key bytes.</param>
        /// <param name="revoked">The revocation status of the encrypted key.</param>
        /// <param name="parentKeyMeta">The metadata for the parent key.</param>
        /// <returns>A new intermediate key record.</returns>
        public static KeyRecord NewIntermediateKeyRecord(DateTimeOffset created, byte[] encryptedKey, bool? revoked, KeyMeta parentKeyMeta)
        {
            if (parentKeyMeta == null)
            {
                throw new ArgumentNullException(nameof(parentKeyMeta));
            }

            return new KeyRecord(created, encryptedKey, revoked, parentKeyMeta);
        }
    }
}
