using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProxyApp.Core.Persistence;

/// <summary>
/// System.Text.Json converter that protects credential strings at rest:
/// serialization writes <see cref="SecretProtector.Protect"/> output
/// (DPAPI blob), deserialization restores plaintext via
/// <see cref="SecretProtector.Unprotect"/>. In-memory model values are ALWAYS
/// plaintext; only the JSON representation is protected.
/// </summary>
public sealed class ProtectedStringJsonConverter : JsonConverter<string?>
{
    public override string? Read(
        ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => SecretProtector.Unprotect(reader.GetString());

    public override void Write(
        Utf8JsonWriter writer, string? value, JsonSerializerOptions options)
        => writer.WriteStringValue(SecretProtector.Protect(value));
}
