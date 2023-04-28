using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace IdentityDapper.Controllers;

[ApiController]
[Route("/[controller]")]
public class AccountController : ControllerBase
{
    private readonly IUserStore<IdentityUser> _userStore;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly SignInManager<IdentityUser> _signInManager;

    public AccountController(
        IUserStore<IdentityUser> userStore,
        UserManager<IdentityUser> userManager,
        SignInManager<IdentityUser> signInManager)
    {
        _userStore = userStore;
        _userManager = userManager;
        _signInManager = signInManager;
    }

    [HttpPost(Name = "CreateUser")]
    public async Task<IdentityResult> CreateUser(string userName)
    {
        var identityUser = new IdentityUser(userName);
        return await _userManager.CreateAsync(identityUser, "1q2w3E*");
    }

    [HttpGet(Name = "GetUser")]
    public async Task<IdentityUser> GetUser(string userName)
    {
        var user = await _userManager.FindByNameAsync(userName);
        return user;
    }

    [HttpGet(template: "~/addClaim", Name = "AddClaim")]
    public async Task<IdentityResult> AddClaim(string userName)
    {
        var user = await _userManager.FindByNameAsync(userName);
        var claim = new Claim(ClaimTypes.DateOfBirth, "1995-01-01", ClaimValueTypes.Date);
        return await _userManager.AddClaimAsync(user, claim);
    }

    [HttpGet(template: "~/listClaim", Name = "ListClaim")]
    public async Task<IList<Claim>> ListClaim(string userName)
    {
        var user = await _userManager.FindByNameAsync(userName);
        return await _userManager.GetClaimsAsync(user);
    }

    [HttpGet(template: "~/listHttpContextClaim", Name = "ListHttpContextClaim")]
    public string ListHttpContextClaim()
    {
        var claims = HttpContext.User.Claims.ToList();
        var simpleClaims = claims.Select(claim => new
        {
            claim = new { claim.Type, claim.Value },
        }).ToList();

        return JsonSerializer.Serialize(simpleClaims);
    }

    [HttpPost(template: "~/signin", Name = "SignIn")]
    public async Task<SignInResult> SignIn(string userName, string password)
    {
        return await _signInManager.PasswordSignInAsync(
            userName,
            password,
            false,
            false);
    }
    
    [HttpGet(template: "~/userAuthenticatorKey", Name = "GetUserAuthenticatorKey")]
    public async Task<string?> GetUserAuthenticatorKey(string userName)
    {
        var user = await _userManager.FindByNameAsync(userName);

        await _userManager.SetTwoFactorEnabledAsync(user, true);
        
        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrWhiteSpace(key))
        {
            // await _userManager.SetAuthenticationTokenAsync(
            //     user,
            //     "[AspNetUserStore]",
            //     "AuthenticatorKey",
            //     "XYBNE4FPX4OM5PPYV6CRZ7ZZNYBI3GPK");
            
            await _userManager.ResetAuthenticatorKeyAsync(user);
            
            // key = await _userManager.GetAuthenticationTokenAsync(
            //     user, 
            //     "[AspNetUserStore]", 
            //     "AuthenticatorKey");

            key = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        return key;
    }

    [HttpPost(template: "~/twoFactorSignIn", Name = "TwoFactorSignIn")]
    public async Task<SignInResult> TwoFactorSignIn(string code)
    {
        return await _signInManager.TwoFactorAuthenticatorSignInAsync(
            code,
            false,
            false);
    }

    [HttpPost(template: "~/updateUser", Name = "UpdateUser")]
    public async Task<IdentityResult> UpdateUser(string userName)
    {
        var identityUser = await _userManager.FindByNameAsync(userName);
        return await _userManager.SetTwoFactorEnabledAsync(identityUser, true);
    }

    [HttpGet(template: "~/externalSignin", Name = "ExternalSignin")]
    public async Task ExternalSignin()
    {
        await _signInManager.SignOutAsync();
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(
            GoogleDefaults.AuthenticationScheme,
            "/externalLoginCallback");
        await HttpContext.ChallengeAsync(GoogleDefaults.AuthenticationScheme, properties);
    }

    [HttpGet(template: "~/externalLoginCallback", Name = "ExternalLoginCallback")]
    public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null)
    {
        var info = await _signInManager.GetExternalLoginInfoAsync();
        var userEmail = info.Principal.FindFirst(ClaimTypes.Email)?.Value.Normalize();

        var result = await _signInManager.ExternalLoginSignInAsync(
            info.LoginProvider,
            info.ProviderKey,
            isPersistent: true,
            bypassTwoFactor: false
        );

        if (result.Succeeded)
            return Redirect("/swagger");

        var user = await _userManager.FindByNameAsync(userEmail);
        if (user == null)
        {
            var identityUser = new IdentityUser(userEmail);
            await CreateUser(identityUser.UserName);
            await AddClaim(identityUser.UserName);
            user = await _userManager.FindByNameAsync(userEmail);
        }

        var userLogin = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
        if (userLogin == null)
        {
            await _userManager.AddLoginAsync(user, new UserLoginInfo(
                info.LoginProvider,
                info.ProviderKey,
                info.ProviderDisplayName
            ));
        }

        await _signInManager.SignOutAsync();
        await _signInManager.SignInAsync(user, isPersistent: true);

        return Redirect("/swagger");
    }
}