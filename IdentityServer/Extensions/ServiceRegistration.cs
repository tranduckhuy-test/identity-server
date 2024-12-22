using IdentityServer.Data;
using IdentityServer.Entities;
using IdentityServer.Helpers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace IdentityServer.Extensions
{
    public static class ServiceRegistration
    {
        public static IServiceCollection AddDataServices(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddDbContext<AppDbContext>(options =>
            {
                options.UseSqlServer(configuration.GetConnectionString("DefaultConnection"));
            });
            return services;
        }

        public static IServiceCollection AddApplicationJwtAuth(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateActor = true,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    ValidateIssuerSigningKey = true,
                    ClockSkew = TimeSpan.Zero,
                    ValidAudience = configuration["JWTSettings:ValidAudience"],
                    ValidIssuer = configuration["JWTSettings:ValidIssuer"],
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(configuration["JWTSettings:SecretKey"]
                        ?? throw new InvalidDataException("JWTSettings:SecretKey is missing in appsettings.json")))
                };
            });
            return services;
        }

        public static IdentityBuilder AddApplicationIdentity<TUser>(this IServiceCollection services) where TUser : class
        {
            return services.AddIdentity<TUser, IdentityRole>(options =>
            {
                options.SignIn.RequireConfirmedEmail = true;

                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequiredLength = 8;

                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
                options.User.RequireUniqueEmail = true;

                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;
            })
            .AddEntityFrameworkStores<AppDbContext>()
            .AddDefaultTokenProviders();
        }

        public static async Task<IApplicationBuilder> SeedDataAsync(this WebApplication app)
        {
            using var scope = app.Services.CreateScope();
            var services = scope.ServiceProvider;
            var context = services.GetRequiredService<AppDbContext>();

            var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = services.GetRequiredService<UserManager<User>>();

            // TODO: Remove this block of code before deploying to production
            await context.Database.EnsureDeletedAsync();

            if (await context.Database.EnsureCreatedAsync())
            {
                var adminRole = new IdentityRole(AppConstants.Roles.Admin);
                var contributorRole = new IdentityRole(AppConstants.Roles.Contributor);
                var userRole = new IdentityRole(AppConstants.Roles.User);

                if (!context.Roles.Any())
                {
                    await roleManager.CreateAsync(adminRole);
                    await roleManager.CreateAsync(contributorRole);
                    await roleManager.CreateAsync(userRole);
                }

                if (!context.Users.Any())
                {
                    var adminUser = new User
                    {
                        Email = "huytde.dev@gmail.com",
                        UserName = "huytde.dev@gmail.com",
                        EmailConfirmed = true
                    };
                    await userManager.CreateAsync(adminUser, "Admin11@");
                    await userManager.AddToRoleAsync(adminUser, AppConstants.Roles.Admin);
                }
            }

            return app;
        }
    }
}
