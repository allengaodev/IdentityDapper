using Dapper;
using Microsoft.AspNetCore.Identity;
using Npgsql;

namespace IdentityDapper;

public class CustomUserStore : IUserStore<IdentityUser>
{
    private readonly IConfiguration _configuration;
    public CustomUserStore(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    
    public async Task<IdentityResult> CreateAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        var connString = _configuration.GetSection("ConnectionStrings").GetValue<string>("DefaultConnection");
        await using var conn = new NpgsqlConnection(connString);
        await conn.OpenAsync();

        int rows;

        await using (var sqlConnection = conn) {
            var command = $"INSERT INTO dbo.AspNetUsers " +
                          "VALUES (@Id, @UserName, @NormalizedUserName, @Email, @NormalizedEmail, @EmailConfirmed, @PasswordHash, @SecurityStamp, @ConcurrencyStamp, " +
                          "@PhoneNumber, @PhoneNumberConfirmed, @TwoFactorEnabled, @LockoutEnd, @LockoutEnabled, @AccessFailedCount);";

            rows = await sqlConnection.ExecuteAsync(command, new {
                user.Id,
                user.UserName,
                user.NormalizedUserName,
                user.Email,
                user.NormalizedEmail,
                user.EmailConfirmed,
                user.PasswordHash,
                user.SecurityStamp,
                user.ConcurrencyStamp,
                user.PhoneNumber,
                user.PhoneNumberConfirmed,
                user.TwoFactorEnabled,
                user.LockoutEnd,
                user.LockoutEnabled,
                user.AccessFailedCount
            });
        }

        return rows == 1 ? IdentityResult.Success : IdentityResult.Failed(new IdentityError {
            Code = nameof(CreateAsync),
            Description = $"Insert User Error"
        });
    }
    
    public async Task<IdentityUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
    {
        var connString = _configuration.GetSection("ConnectionStrings").GetValue<string>("DefaultConnection");
        await using var conn = new NpgsqlConnection(connString);
        await conn.OpenAsync();
        
        await using (var sqlConnection = conn)
        {
            var command = "SELECT * " +
                          "FROM dbo.AspNetUsers " +
                          "WHERE NormalizedUserName = @NormalizedUserName;";
            
            return await sqlConnection.QuerySingleOrDefaultAsync<IdentityUser>(command, new
            {
                NormalizedUserName = normalizedUserName
            });
        }
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
    }
    
    public Task<string> GetUserIdAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<string?> GetUserNameAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task SetUserNameAsync(IdentityUser user, string? userName, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<string?> GetNormalizedUserNameAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task SetNormalizedUserNameAsync(IdentityUser user, string? normalizedName, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<IdentityResult> UpdateAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<IdentityResult> DeleteAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<IdentityUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}