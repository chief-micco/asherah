using System;
using System.Data;
using System.Linq;
using System.Threading.Tasks;

namespace GoDaddy.Asherah.AppEncryption.Metastore
{
    /// <summary>
    /// Provides a volatile implementation of <see cref="IKeyMetastore"/> for key records using a
    /// <see cref="System.Data.DataTable"/>. NOTE: This should NEVER be used in a production environment.
    /// </summary>
    public class InMemoryKeyMetastore : IKeyMetastore, IDisposable
    {
        private readonly DataTable _dataTable;

        /// <summary>
        /// Initializes a new instance of the <see cref="InMemoryKeyMetastore"/> class, with 3 columns.
        /// <code>
        /// keyId | created | keyRecord
        /// ----- | ------- | ---------
        ///       |         |
        ///       |         |
        /// </code>
        /// Uses 'keyId' and 'created' as the primary key.
        /// </summary>
        public InMemoryKeyMetastore()
        {
            _dataTable = new DataTable();
            _dataTable.Columns.Add("keyId", typeof(string));
            _dataTable.Columns.Add("created", typeof(DateTimeOffset));
            _dataTable.Columns.Add("keyRecord", typeof(KeyRecord));
            _dataTable.PrimaryKey = new[] { _dataTable.Columns["keyId"], _dataTable.Columns["created"] };
        }

        /// <inheritdoc />
        public Task<(bool found, IKeyRecord keyRecord)> TryLoadAsync(string keyId, DateTimeOffset created)
        {
            lock (_dataTable)
            {
                var dataRows = _dataTable.Rows.Cast<DataRow>()
                    .Where(row => row["keyId"].Equals(keyId)
                                  && row["created"].Equals(created))
                    .ToList();
                if (dataRows.Count == 0)
                {
                    return Task.FromResult((false, (IKeyRecord)null));
                }

                var keyRecord = (IKeyRecord)dataRows.Single()["keyRecord"];
                return Task.FromResult((true, keyRecord));
            }
        }

        /// <inheritdoc />
        public Task<(bool found, IKeyRecord keyRecord)> TryLoadLatestAsync(string keyId)
        {
            lock (_dataTable)
            {
                var dataRows = _dataTable.Rows.Cast<DataRow>()
                    .Where(row => row["keyId"].Equals(keyId))
                    .OrderBy(row => row["created"])
                    .ToList();

                // Need to check if empty as Last will throw an exception instead of returning null
                if (dataRows.Count == 0)
                {
                    return Task.FromResult((false, (IKeyRecord)null));
                }

                var keyRecord = (IKeyRecord)dataRows.Last()["keyRecord"];
                return Task.FromResult((true, keyRecord));
            }
        }

        /// <inheritdoc />
        public Task<bool> StoreAsync(string keyId, DateTimeOffset created, IKeyRecord keyRecord)
        {
            lock (_dataTable)
            {
                var dataRows = _dataTable.Rows.Cast<DataRow>()
                    .Where(row => row["keyId"].Equals(keyId)
                                  && row["created"].Equals(created))
                    .ToList();
                if (dataRows.Count > 0)
                {
                    return Task.FromResult(false);
                }

                _dataTable.Rows.Add(keyId, created, keyRecord);
                return Task.FromResult(true);
            }
        }

        /// <inheritdoc />
        public string GetKeySuffix()
        {
            return string.Empty;
        }

        /// <summary>
        /// Disposes of the managed resources.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }

        /// <summary>
        /// Disposes of the managed resources.
        /// </summary>
        /// <param name="disposing">True if called from Dispose, false if called from finalizer.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!disposing)
            {
                return;
            }

            lock (_dataTable)
            {
                _dataTable?.Dispose();
            }
        }
    }
}
