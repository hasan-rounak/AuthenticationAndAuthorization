using System;
using System.Security.Claims;

namespace AuthenticationAndAutorization.Authentication
{
    public interface IJwtAuthManager
    {
        JwtAuthResult GenerateTokens(string username, Claim[] claims, DateTime now);
    }
}
