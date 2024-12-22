namespace IdentityServer.Dtos.Responses
{
    public class UserLoginResponseDto
    {
        public string UserId { get; set; } = string.Empty;

        public string AccessToken { get; set; } = string.Empty;

        public string RefreshToken { get; set; } = string.Empty;
    }
}
