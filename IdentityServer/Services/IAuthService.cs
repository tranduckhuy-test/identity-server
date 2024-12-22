using IdentityServer.Dtos;
using IdentityServer.Entities;

namespace IdentityServer.Services
{
    public interface IAuthService
    {
        Task<(string accessToken, string refreshToken)> RefreshToken(RefreshTokenDto request);
        Task<(string accessToken, string refreshToken)> GenerateToken(User user, IList<string> roles, bool populateExp);
        Task Logout(string userId, string accessToken);
    }
}
