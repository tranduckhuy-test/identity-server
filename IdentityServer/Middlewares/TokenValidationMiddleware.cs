using IdentityServer.Services;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityServer.Middlewares
{
    public class TokenValidationMiddleware
    {
        private readonly RequestDelegate _next;

        public TokenValidationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, IServiceProvider serviceProvider)
        {
            // Bypass if the endpoint has [AllowAnonymous] attribute
            var endpoint = context.GetEndpoint();
            if (endpoint?.Metadata?.GetMetadata<Microsoft.AspNetCore.Authorization.IAllowAnonymous>() != null)
            {
                await _next(context);
                return;
            }

            var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

            if (!string.IsNullOrEmpty(token))
            {
                using (var scope = serviceProvider.CreateScope())
                {
                    var tokenBlacklistService = scope.ServiceProvider.GetRequiredService<TokenBlackListService>();

                    if (await tokenBlacklistService.IsTokenBlacklistedAsync(token))
                    {
                        context.Response.StatusCode = 401; // Unauthorized
                        await context.Response.WriteAsync("Token is blacklisted.");
                        return;
                    }
                }
            }

            await _next(context);
        }
    }

}
