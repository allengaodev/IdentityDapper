using Microsoft.AspNetCore.Authorization;

namespace IdentityDapper.Permissions;

public class MinimumAgeRequirement : IAuthorizationRequirement
{
    public MinimumAgeRequirement(int minimumAge)
    {
        MinimumAge = minimumAge;
    }

    public int MinimumAge { get; }
}