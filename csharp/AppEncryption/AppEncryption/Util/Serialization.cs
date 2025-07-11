using System.Text.Encodings.Web;
using System.Text.Json;

namespace GoDaddy.Asherah.AppEncryption.Util
{
    internal static class Serialization
    {
        static Serialization()
        {
            NoFormatting = new JsonSerializerOptions
            {
                WriteIndented = false,
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            };

            BytesParsingOptions = new JsonDocumentOptions
            {
                AllowTrailingCommas = true,
                CommentHandling = JsonCommentHandling.Skip,
            };
        }

        public static JsonSerializerOptions NoFormatting { get; }

        public static JsonDocumentOptions BytesParsingOptions { get; }
    }
}
