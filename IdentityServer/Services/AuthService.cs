using IdentityServer.Dtos;
using IdentityServer.Entities;
using IdentityServer.Helpers;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace IdentityServer.Services
{
    public class AuthService : IAuthService
    {
        private readonly JwtHandler _jwtHandler;
        private readonly UserManager<User> _userManager;
        private readonly TokenBlackListService _tokenBlackListService;

        public AuthService(JwtHandler jwtHandler, UserManager<User> userManager, TokenBlackListService tokenBlackListService)
        {
            _jwtHandler = jwtHandler;
            _userManager = userManager;
            _tokenBlackListService = tokenBlackListService;
        }

        public async Task<(string accessToken, string refreshToken)> GenerateToken(User user, IList<string> roles, bool populateExp)
        {
            var signingCredentials = _jwtHandler.GetSigningCredentials();
            var claims = _jwtHandler.GetClaims(user, roles);
            var tokenOptions = _jwtHandler.GenerateTokenOptions(signingCredentials, claims);

            var refreshToken = _jwtHandler.GenerateRefreshToken();

            user.RefreshToken = refreshToken;

            if (populateExp)
            {
                user.RefreshTokenExpiryTime = DateTime.Now.AddDays(7);
            }

            await _userManager.UpdateAsync(user);

            var accessToken = new JwtSecurityTokenHandler().WriteToken(tokenOptions);

            return (accessToken, refreshToken);
        }

        public async Task Logout(string userId, string accessToken)
        {
            var user = await _userManager.FindByIdAsync(userId);

            if (user != null)
            {
                user.RefreshToken = null!;
                user.RefreshTokenExpiryTime = null; 
                await _userManager.UpdateAsync(user);
            }

            var expiry = GetTokenExpiry(accessToken);
            if (expiry > DateTime.UtcNow)
            {
                await _tokenBlackListService.BlacklistTokenAsync(accessToken, expiry);
            }
        }

        private DateTime GetTokenExpiry(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);
            return jwtToken.ValidTo;
        }

        public async Task<(string accessToken, string refreshToken)> RefreshToken(RefreshTokenDto request)
        {
            var principal = _jwtHandler.GetPrincipalFromExpiredToken(request.AccessToken);

            var username = principal.Identity?.Name;

            if (username == null)
            {
                throw new SecurityTokenException("Invalid token");
            }

            var user = await _userManager.FindByNameAsync(username);

            if (user == null || user.RefreshToken != request.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                throw new SecurityTokenException("Invalid token");
            }

            return await GenerateToken(user, await _userManager.GetRolesAsync(user), false);
        }
    }
}
