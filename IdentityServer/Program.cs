using EmailService;
using IdentityServer.Entities;
using IdentityServer.Extensions;
using IdentityServer.Helpers;
using IdentityServer.Middlewares;
using IdentityServer.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

// SuppressModelStateInvalidFilter can be used to disable the automatic 400 response for invalid models.
builder.Services.Configure<ApiBehaviorOptions>(options =>
{
    options.SuppressModelStateInvalidFilter = true;
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(setup =>
{
    setup.SwaggerDoc("v1", new OpenApiInfo { Title = "Identity API", Version = "v1" });

    // Include 'SecurityScheme' to use JWT Authentication
    var jwtSecurityScheme = new OpenApiSecurityScheme
    {
        BearerFormat = "JWT",
        Name = "JWT Authentication",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = JwtBearerDefaults.AuthenticationScheme,
        Description = "Put **_ONLY_** your JWT Bearer token on textbox below!",

        Reference = new OpenApiReference
        {
            Id = JwtBearerDefaults.AuthenticationScheme,
            Type = ReferenceType.SecurityScheme
        }
    };

    setup.AddSecurityDefinition(jwtSecurityScheme.Reference.Id, jwtSecurityScheme);

    setup.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        { jwtSecurityScheme, Array.Empty<string>() }
    });

});

builder.Services.AddAutoMapper(typeof(Program));

builder.Services.AddApplicationIdentity<User>();
builder.Services.AddApplicationJwtAuth(builder.Configuration);

builder.Services.AddAuthorization();

builder.Services.AddDataServices(builder.Configuration);

builder.Services.AddSingleton<JwtHandler>();
builder.Services.AddScoped<IAuthService, AuthService>();

var emailConfig = builder.Configuration.GetSection("EmailConfiguration").Get<EmailConfiguration>();
builder.Services.AddSingleton(emailConfig ?? throw new InvalidDataException("EmailConfiguration is missing in appsettings.json"));
builder.Services.AddScoped<IEmailSender, EmailSender>();

builder.Services.Configure<DataProtectionTokenProviderOptions>(opt =>
{
    opt.TokenLifespan = TimeSpan.FromMinutes(1);
});

builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = builder.Configuration["Redis:ConnectionString"];
    options.InstanceName = builder.Configuration["Redis:InstanceName"];
});

builder.Services.AddScoped<TokenBlackListService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
    await app.SeedDataAsync();
}

app.UseHttpsRedirection();

app.UseMiddleware<TokenValidationMiddleware>();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

await app.RunAsync();
