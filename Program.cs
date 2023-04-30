using System.Security.Claims;
using IdentityDapper;
using IdentityDapper.Permissions;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

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
    .AddCookie(IdentityConstants.TwoFactorRememberMeScheme, o =>
    {
        o.Events = new CookieAuthenticationEvents
        {
            OnValidatePrincipal = SecurityStampValidator.ValidateAsync<ITwoFactorSecurityStampValidator>
        };
    })
    .AddCookie(IdentityConstants.TwoFactorUserIdScheme, options =>
    {
        options.ExpireTimeSpan = TimeSpan.FromMinutes(10);
    })
    .AddCookie(IdentityConstants.ExternalScheme, o =>
    {
        o.ExpireTimeSpan = TimeSpan.FromMinutes(10);
    })
    .AddOpenIdConnect("Google", o =>
    {
        o.Authority = "https://accounts.google.com";
        o.ClientId = configuration["Authentication:Google:ClientId"];
        o.ClientSecret = configuration["Authentication:Google:ClientSecret"];
        o.ResponseType = OpenIdConnectResponseType.Code;
        o.GetClaimsFromUserInfoEndpoint = true;
        o.Scope.Add("openid");
        o.Scope.Add("email");

        o.CallbackPath = "/signin-google";
        o.SaveTokens = true;
        o.SignInScheme = IdentityConstants.ExternalScheme;
    });
    // .AddGoogle(GoogleDefaults.AuthenticationScheme, o =>
    // {
    //     o.ClientId = configuration["Authentication:Google:ClientId"];
    //     o.ClientSecret = configuration["Authentication:Google:ClientSecret"];
    //     o.SignInScheme = IdentityConstants.ExternalScheme;
    // });

// builder.Services.AddIdentity<IdentityUser, IdentityRole>();
builder.Services.AddIdentityCore<IdentityUser>()
    .AddUserStore<CustomUserStore>()
    .AddSignInManager<SignInManager<IdentityUser>>()
    .AddTokenProvider<AuthenticatorTokenProvider<IdentityUser>>(TokenOptions.DefaultAuthenticatorProvider);

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