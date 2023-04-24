using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
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
    public async Task<IdentityResult> CreateUser()
    {
        var userName = "User1";
        var identityUser = new IdentityUser(userName);
        return await _userManager.CreateAsync(identityUser, "1q2w3E*");
    }

    [HttpGet(Name = "GetUser")]
    public async Task<IdentityUser> GetUser()
    {
        var userName = "User1";
        new Claim(ClaimTypes.DateOfBirth, "1995-01-01", ClaimValueTypes.Date);
        return await _userManager.FindByNameAsync(userName);
    }

    [HttpGet(template: "~/addClaim", Name = "AddClaim")]
    public async Task<IdentityResult> AddClaim()
    {
        var userName = "User1";
        var user = await _userManager.FindByNameAsync(userName);
        var claim = new Claim(ClaimTypes.DateOfBirth, "1995-01-01", ClaimValueTypes.Date);
        return await _userManager.AddClaimAsync(user, claim);
    }

    [HttpGet(template: "~/listClaim", Name = "ListClaim")]
    public async Task<IList<Claim>> ListClaim()
    {
        var userName = "User1";
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

    [HttpGet(template: "~/externalSignin", Name = "ExternalSignin")]
    public async Task ExternalSignin()
    {
        await HttpContext.ChallengeAsync(IdentityConstants.ExternalScheme,
            new AuthenticationProperties()
            {
                RedirectUri = "/swagger/index.html"
            });
    }
}