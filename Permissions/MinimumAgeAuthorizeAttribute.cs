using Microsoft.AspNetCore.Authorization;

namespace IdentityDapper.Permissions;

public class MinimumAgeAuthorizeAttribute : AuthorizeAttribute
{
    private const string POLICY_PREFIX = "MinimumAge";

    public MinimumAgeAuthorizeAttribute(int age)
    {
        Age = age;
    }

    public int Age
    {
        get
        {
            if (int.TryParse(Policy.Substring(POLICY_PREFIX.Length), out var age))
            {
                return age;
            }
    
            return default;
        }
        set
        {
            Policy = $"{POLICY_PREFIX}{value.ToString()}";
        }
    }
}