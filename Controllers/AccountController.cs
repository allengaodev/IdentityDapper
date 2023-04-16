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
        return await _userManager.FindByNameAsync(userName);
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
}