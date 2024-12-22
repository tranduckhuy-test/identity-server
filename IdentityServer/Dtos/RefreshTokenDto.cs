using System.ComponentModel.DataAnnotations;

namespace IdentityServer.Dtos
{
    public class RefreshTokenDto
    {
        [Required(ErrorMessage = "Refresh token is required.")]
        public string AccessToken { get; set; } = null!;

        [Required(ErrorMessage = "Refresh token is required.")]
        public string RefreshToken { get; set; } = null!;
    }
}
