using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace GoDaddy.Asherah.AppEncryption.Metastore
{
    /// <summary>
    /// Provides a volatile implementation of <see cref="IKeyMetastore"/> for key records using a
    /// <see cref="System.Data.DataTable"/>. NOTE: This should NEVER be used in a production environment.
    /// </summary>
    public class InMemoryKeyMetastoreImpl : IKeyMetastore, IDisposable
    {
        private readonly DataTable dataTable;

        /// <summary>
        /// Initializes a new instance of the <see cref="InMemoryKeyMetastoreImpl"/> class, with 3 columns.
        /// <code>
        /// keyId | created | keyRecord
        /// ----- | ------- | ---------
        ///       |         |
        ///       |         |
        /// </code>
        /// Uses 'keyId' and 'created' as the primary key.
        /// </summary>
        public InMemoryKeyMetastoreImpl()
        {
            dataTable = new DataTable();
            dataTable.Columns.Add("keyId", typeof(string));
            dataTable.Columns.Add("created", typeof(DateTimeOffset));
            dataTable.Columns.Add("keyRecord", typeof(KeyRecord));
            dataTable.PrimaryKey = new[] { dataTable.Columns["keyId"], dataTable.Columns["created"] };
        }

        /// <inheritdoc />
        public Task<(bool found, KeyRecord keyRecord)> TryLoadAsync(string keyId, DateTimeOffset created)
        {
            lock (dataTable)
            {
                List<DataRow> dataRows = dataTable.Rows.Cast<DataRow>()
                    .Where(row => row["keyId"].Equals(keyId)
                                  && row["created"].Equals(created))
                    .ToList();
                if (dataRows.Count == 0)
                {
                    return Task.FromResult((false, (KeyRecord)null));
                }

                var keyRecord = (KeyRecord)dataRows.Single()["keyRecord"];
                return Task.FromResult((true, keyRecord));
            }
        }

        /// <inheritdoc />
        public Task<(bool found, KeyRecord keyRecord)> TryLoadLatestAsync(string keyId)
        {
            lock (dataTable)
            {
                List<DataRow> dataRows = dataTable.Rows.Cast<DataRow>()
                    .Where(row => row["keyId"].Equals(keyId))
                    .OrderBy(row => row["created"])
                    .ToList();

                // Need to check if empty as Last will throw an exception instead of returning null
                if (dataRows.Count == 0)
                {
                    return Task.FromResult((false, (KeyRecord)null));
                }

                var keyRecord = (KeyRecord)dataRows.Last()["keyRecord"];
                return Task.FromResult((true, keyRecord));
            }
        }

        /// <inheritdoc />
        public Task<bool> StoreAsync(string keyId, DateTimeOffset created, KeyRecord keyRecord)
        {
            lock (dataTable)
            {
                List<DataRow> dataRows = dataTable.Rows.Cast<DataRow>()
                    .Where(row => row["keyId"].Equals(keyId)
                                  && row["created"].Equals(created))
                    .ToList();
                if (dataRows.Count > 0)
                {
                    return Task.FromResult(false);
                }

                dataTable.Rows.Add(keyId, created, keyRecord);
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
            if (disposing)
            {
                dataTable?.Dispose();
            }
        }
    }
}
