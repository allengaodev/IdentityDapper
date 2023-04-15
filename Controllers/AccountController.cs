using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityDapper.Controllers;

[ApiController]
[Route("[controller]")]
public class AccountController : ControllerBase
{
    private readonly IUserStore<IdentityUser> _userStore;
    private readonly UserManager<IdentityUser> _userManager;
    public AccountController(IUserStore<IdentityUser> userStore, UserManager<IdentityUser> userManager)
    {
        _userStore = userStore;
        _userManager = userManager;
    }
    
    [HttpPost(Name = "CreateUser")]
    public async Task<IdentityResult> CreateUser()
    {
        var userName = "User1";
        var identityUser = new IdentityUser(userName);
        return await _userManager.CreateAsync(identityUser);
    }
    
    [HttpGet(Name = "GetUser")]
    public async Task<IdentityUser> GetUser()
    {
        var userName = "User1";
        return await _userManager.FindByNameAsync(userName);
    }
}