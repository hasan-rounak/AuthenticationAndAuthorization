using System.Text.Json.Serialization;

namespace AuthenticationAndAutorization.Model
{
    public class ImpersonationRequest
    {
        [JsonPropertyName("username")]
        public string UserName { get; set; }
    }
}
