using System.Security.Claims;
using IdentityDapper;
using IdentityDapper.Permissions;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;
// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddSingleton<IAuthorizationPolicyProvider, MinimumAgePolicyProvider>();
builder.Services.AddSingleton<IAuthorizationHandler, MinimumAgeAuthorizationHandler>();

builder.Services.AddAuthorization(option =>
{
    option.AddPolicy("birthday", builder =>
    {
        builder
            .RequireAuthenticatedUser()
            .RequireClaim(ClaimTypes.DateOfBirth);
    });
});

builder.Services
    .AddAuthentication(o =>
    {
        o.DefaultScheme = IdentityConstants.ApplicationScheme;
    })
    .AddCookie(IdentityConstants.ApplicationScheme, options =>
    {
        options.ExpireTimeSpan = TimeSpan.FromMinutes(10);
    })
    .AddCookie(IdentityConstants.TwoFactorUserIdScheme, options =>
    {
        options.ExpireTimeSpan = TimeSpan.FromMinutes(10);
    })
    .AddCookie(IdentityConstants.ExternalScheme, o =>
    {
        o.ExpireTimeSpan = TimeSpan.FromMinutes(10);
    })
    .AddGoogle(GoogleDefaults.AuthenticationScheme, o =>
    {
        o.ClientId = configuration["Authentication:Google:ClientId"];
        o.ClientSecret = configuration["Authentication:Google:ClientSecret"];
        o.SignInScheme = IdentityConstants.ExternalScheme;
    });

// builder.Services.AddIdentity<IdentityUser, IdentityRole>();
builder.Services.AddIdentityCore<IdentityUser>()
    .AddUserStore<CustomUserStore>()
    .AddSignInManager<SignInManager<IdentityUser>>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();