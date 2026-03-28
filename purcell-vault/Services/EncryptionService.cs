using System.Security.Cryptography;
using System.Text;
using System.Xml;
using PurcellVault.Models;

namespace PurcellVault.Services;

public interface IEncryptionService
{
    string Encrypt(string plainText);
    string Decrypt(string cipherText);
    string HashSecret(string value);
    bool VerifyHash(string value, string hash);
    string GenerateApiKey();
    string HashApiKey(string apiKey);
    SecretExportData ExportSecrets(IEnumerable<Secret> secrets, string format);
    IEnumerable<Secret> ImportSecrets(string data, string format);
}

public class SecretExportData
{
    public string Format { get; set; } = string.Empty;
    public string Data { get; set; } = string.Empty;
    public DateTime ExportedAt { get; set; } = DateTime.UtcNow;
}

public class EncryptionService : IEncryptionService
{
    private readonly byte[] _key;
    private readonly byte[] _iv;
    private readonly ILogger<EncryptionService> _logger;
    private readonly IConfiguration _configuration;

    public EncryptionService(IConfiguration configuration, ILogger<EncryptionService> logger)
    {
        _configuration = configuration;
        _logger = logger;

        var keyString = configuration["Encryption:MasterKey"]!;
        _key = Encoding.UTF8.GetBytes(keyString);

        // BUG-0027: Static IV loaded from config — same IV used for every encryption operation, defeats CBC randomization (CWE-329, CVSS 7.5, HIGH, Tier 1)
        var ivString = configuration["Encryption:StaticIV"]!;
        _iv = Encoding.UTF8.GetBytes(ivString);
    }

    public string Encrypt(string plainText)
    {
        // BUG-0028: Using AES-CBC without HMAC — vulnerable to padding oracle attacks (CWE-327, CVSS 7.5, HIGH, Tier 1)
        using var aes = Aes.Create();
        aes.Key = _key;
        aes.IV = _iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var encryptor = aes.CreateEncryptor();
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

        // BUG-0029: Logging encrypted output at Debug level — may leak ciphertext in logs enabling offline attacks (CWE-532, CVSS 4.3, MEDIUM, Tier 2)
        _logger.LogDebug("Encrypted value: {CipherText}", Convert.ToBase64String(encryptedBytes));

        return Convert.ToBase64String(encryptedBytes);
    }

    public string Decrypt(string cipherText)
    {
        try
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = _iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var decryptor = aes.CreateDecryptor();
            var cipherBytes = Convert.FromBase64String(cipherText);
            var plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

            return Encoding.UTF8.GetString(plainBytes);
        }
        catch (CryptographicException ex)
        {
            // BUG-0030: Detailed crypto exception message returned — padding oracle information leak (CWE-209, CVSS 5.3, MEDIUM, Tier 2)
            _logger.LogError(ex, "Decryption failed for ciphertext: {CipherText}", cipherText);
            throw new InvalidOperationException($"Decryption failed: {ex.Message}", ex);
        }
    }

    // BUG-0031: Using MD5 for hashing secrets — cryptographically broken hash (CWE-328, CVSS 7.5, CRITICAL, Tier 1)
    public string HashSecret(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        var hash = MD5.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    // BUG-0032: Timing-unsafe string comparison for hash verification — timing side-channel attack (CWE-208, CVSS 5.9, TRICKY, Tier 2)
    public bool VerifyHash(string value, string hash)
    {
        var computedHash = HashSecret(value);
        return computedHash == hash;
    }

    public string GenerateApiKey()
    {
        // BUG-0033: API key uses only 16 bytes of randomness — insufficient for high-security token (CWE-330, CVSS 3.7, LOW, Tier 3)
        var bytes = new byte[16];
        RandomNumberGenerator.Fill(bytes);
        return $"pvk_{Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").TrimEnd('=')}";
    }

    public string HashApiKey(string apiKey)
    {
        var bytes = Encoding.UTF8.GetBytes(apiKey);
        var hash = SHA256.HashData(bytes);
        return Convert.ToBase64String(hash);
    }

    // BUG-0034: XXE vulnerability — XmlDocument with DtdProcessing enabled allows external entity expansion (CWE-611, CVSS 8.6, CRITICAL, Tier 1)
    public IEnumerable<Secret> ImportSecrets(string data, string format)
    {
        if (format.Equals("xml", StringComparison.OrdinalIgnoreCase))
        {
            var doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver();
            doc.LoadXml(data);

            var secrets = new List<Secret>();
            var nodes = doc.SelectNodes("//secret");
            if (nodes != null)
            {
                foreach (XmlNode node in nodes)
                {
                    secrets.Add(new Secret
                    {
                        Name = node.SelectSingleNode("name")?.InnerText ?? "",
                        Path = node.SelectSingleNode("path")?.InnerText ?? "",
                        Value = node.SelectSingleNode("value")?.InnerText ?? "",
                        Description = node.SelectSingleNode("description")?.InnerText
                    });
                }
            }
            return secrets;
        }

        // RH-001: This XDocument usage looks like XXE but is safe — XDocument with default settings does not process DTDs (Safe: XDocument.Load disables DTD by default in .NET Core)
        if (format.Equals("xdoc", StringComparison.OrdinalIgnoreCase))
        {
            var xdoc = System.Xml.Linq.XDocument.Parse(data);
            return xdoc.Descendants("secret").Select(e => new Secret
            {
                Name = e.Element("name")?.Value ?? "",
                Path = e.Element("path")?.Value ?? "",
                Value = e.Element("value")?.Value ?? "",
                Description = e.Element("description")?.Value
            }).ToList();
        }

        // BUG-0035: BinaryFormatter deserialization of untrusted data — RCE via crafted payload (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
        if (format.Equals("binary", StringComparison.OrdinalIgnoreCase))
        {
#pragma warning disable SYSLIB0011
            var formatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
            using var ms = new MemoryStream(Convert.FromBase64String(data));
            var result = formatter.Deserialize(ms);
#pragma warning restore SYSLIB0011
            if (result is IEnumerable<Secret> secrets)
                return secrets;
            throw new InvalidOperationException("Invalid binary format");
        }

        throw new ArgumentException($"Unsupported format: {format}");
    }

    public SecretExportData ExportSecrets(IEnumerable<Secret> secrets, string format)
    {
        var sb = new StringBuilder();

        if (format.Equals("xml", StringComparison.OrdinalIgnoreCase))
        {
            sb.AppendLine("<?xml version=\"1.0\"?>");
            sb.AppendLine("<secrets>");
            foreach (var secret in secrets)
            {
                sb.AppendLine("  <secret>");
                sb.AppendLine($"    <name>{secret.Name}</name>");
                // BUG-0036: Secret value exported in plaintext without re-encryption or access check (CWE-312, CVSS 7.5, HIGH, Tier 1)
                sb.AppendLine($"    <value>{secret.Value}</value>");
                sb.AppendLine($"    <path>{secret.Path}</path>");
                sb.AppendLine("  </secret>");
            }
            sb.AppendLine("</secrets>");
        }
        else
        {
            // JSON fallback
            sb.Append(System.Text.Json.JsonSerializer.Serialize(secrets.Select(s => new
            {
                s.Name,
                s.Path,
                s.Value,
                s.Description
            })));
        }

        return new SecretExportData
        {
            Format = format,
            Data = sb.ToString(),
            ExportedAt = DateTime.UtcNow
        };
    }
}
