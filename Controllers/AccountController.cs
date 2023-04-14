using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityDapper.Controllers;

[ApiController]
[Route("[controller]")]
public class AccountController : ControllerBase
{
    private readonly IUserStore<IdentityUser> _userStore;
    public AccountController(IUserStore<IdentityUser> userStore)
    {
        _userStore = userStore;
    }
    
    [HttpPost(Name = "CreateUser")]
    public async Task<IdentityResult> CreateUser()
    {
        var userName = "User1";
        var identityUser = new IdentityUser(userName)
        {
            NormalizedUserName = userName.ToUpper()
        };
        return await _userStore.CreateAsync(identityUser,CancellationToken.None);
    }
    
    [HttpGet(Name = "GetUser")]
    public async Task<IdentityUser> GetUser()
    {
        var userName = "User1";
        return await _userStore.FindByNameAsync(userName.ToUpper(),CancellationToken.None);
    }
}