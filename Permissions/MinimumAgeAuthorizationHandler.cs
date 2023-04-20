using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace IdentityDapper.Permissions;

public class MinimumAgeAuthorizationHandler : AuthorizationHandler<MinimumAgeRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        MinimumAgeRequirement requirement)
    {
        if (!context.User.HasClaim(c => c.Type == ClaimTypes.DateOfBirth))
        {
            return Task.FromResult(0);
        }

        DateTime dateOfBirth =Convert.ToDateTime(context.User?.FindFirst(c => c.Type == ClaimTypes.DateOfBirth)?.Value);
        
        int age = DateTime.Today.Year - dateOfBirth.Year;
        if (dateOfBirth > DateTime.Today.AddYears(-age)) age--;

        if (age > requirement.MinimumAge)
        {
            context.Succeed(requirement);
        }

        return Task.FromResult(0);
    }
}