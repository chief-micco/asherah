using System;

namespace GoDaddy.Asherah.AppEncryption.Models
{
    /// <summary>
    /// Represents metadata for a parent key.
    /// </summary>
    public class KeyMeta
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyMeta"/> class.
        /// </summary>
        ///
        /// <param name="id">The key identifier.</param>
        /// <param name="created">The creation time of the key.</param>
        public KeyMeta(string id, DateTimeOffset created)
        {
            Id = id ?? throw new ArgumentNullException(nameof(id));
            Created = created;
        }

        /// <summary>
        /// Gets the key identifier.
        /// </summary>
        public string Id { get; }

        /// <summary>
        /// Gets the creation time of the key.
        /// </summary>
        public DateTimeOffset Created { get; }
    }
}
