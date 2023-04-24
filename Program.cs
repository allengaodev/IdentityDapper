using System.Security.Claims;
using IdentityDapper;
using IdentityDapper.Permissions;
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
            .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme)
            .RequireClaim(ClaimTypes.DateOfBirth);
    });
});

builder.Services
    .AddAuthentication(IdentityConstants.ApplicationScheme)
    .AddCookie(IdentityConstants.ApplicationScheme, options =>
    {
        options.ExpireTimeSpan = TimeSpan.FromSeconds(10);
    }).AddGoogle(IdentityConstants.ExternalScheme, o =>
    {
        o.ClientId = configuration["Authentication:Google:ClientId"];
        o.ClientSecret = configuration["Authentication:Google:ClientSecret"];
    });
// builder.Services.TryAddScoped<UserManager<IdentityUser>>();
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