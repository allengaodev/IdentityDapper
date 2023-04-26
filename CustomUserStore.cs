using System.Security.Claims;
using Dapper;
using Microsoft.AspNetCore.Identity;
using Npgsql;

namespace IdentityDapper;

public class CustomUserStore
    : IUserStore<IdentityUser>,
        IUserPasswordStore<IdentityUser>,
        IUserClaimStore<IdentityUser>,
        IUserLoginStore<IdentityUser>
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

        await using (var sqlConnection = conn)
        {
            var command = $"INSERT INTO dbo.AspNetUsers " +
                          "VALUES (@Id, @UserName, @NormalizedUserName, @Email, @NormalizedEmail, @EmailConfirmed, @PasswordHash, @SecurityStamp, @ConcurrencyStamp, " +
                          "@PhoneNumber, @PhoneNumberConfirmed, @TwoFactorEnabled, @LockoutEnd, @LockoutEnabled, @AccessFailedCount);";

            rows = await sqlConnection.ExecuteAsync(command, new
            {
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

        return rows == 1
            ? IdentityResult.Success
            : IdentityResult.Failed(new IdentityError
            {
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
        cancellationToken.ThrowIfCancellationRequested();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user), $"Parameter {nameof(user)} cannot be null.");
        }

        return Task.FromResult(user.Id);
    }

    public Task<string?> GetUserNameAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user), $"Parameter {nameof(user)} cannot be null.");
        }

        return Task.FromResult(user.UserName);
    }

    public Task SetUserNameAsync(IdentityUser user, string? userName, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<string?> GetNormalizedUserNameAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task SetNormalizedUserNameAsync(
        IdentityUser user,
        string? normalizedName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user), $"Parameter {nameof(user)} cannot be null.");
        }

        user.NormalizedUserName = normalizedName;
        return Task.CompletedTask;
    }

    public async Task<IdentityResult> UpdateAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user), $"Parameter {nameof(user)} cannot be null.");
        }

        user.ConcurrencyStamp = Guid.NewGuid().ToString();

        var connString = _configuration.GetSection("ConnectionStrings").GetValue<string>("DefaultConnection");
        await using var conn = new NpgsqlConnection(connString);
        await conn.OpenAsync();

        await using (var sqlConnection = conn)
        {
            var updateUserCommand =
                $"UPDATE dbo.AspNetUsers " +
                "SET UserName = @UserName, NormalizedUserName = @NormalizedUserName, Email = @Email, NormalizedEmail = @NormalizedEmail, EmailConfirmed = @EmailConfirmed, " +
                "PasswordHash = @PasswordHash, SecurityStamp = @SecurityStamp, ConcurrencyStamp = @ConcurrencyStamp, PhoneNumber = @PhoneNumber, " +
                "PhoneNumberConfirmed = @PhoneNumberConfirmed, TwoFactorEnabled = @TwoFactorEnabled, LockoutEnd = @LockoutEnd, LockoutEnabled = @LockoutEnabled, " +
                "AccessFailedCount = @AccessFailedCount " +
                "WHERE Id = @Id;";

            await using var transaction = await sqlConnection.BeginTransactionAsync();
            await sqlConnection.ExecuteAsync(updateUserCommand, new
            {
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
                user.AccessFailedCount,
                user.Id
            }, transaction);

            try
            {
                await transaction.CommitAsync();
            }
            catch
            {
                try
                {
                    await transaction.RollbackAsync();
                }
                catch
                {
                    return IdentityResult.Failed(new IdentityError
                    {
                        Code = nameof(UpdateAsync),
                        Description =
                            $"User with email {user.Email} could not be updated. Operation could not be rolled back."
                    });
                }

                return IdentityResult.Failed(new IdentityError
                {
                    Code = nameof(UpdateAsync),
                    Description = $"User with email {user.Email} could not be updated. Operation was rolled back."
                });
            }
        }

        return IdentityResult.Success;
    }

    public Task<IdentityResult> DeleteAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<IdentityUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task SetSecurityStampAsync(IdentityUser user, string stamp, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<string?> GetSecurityStampAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task SetPasswordHashAsync(IdentityUser user, string? passwordHash, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user), $"Parameter {nameof(user)} cannot be null.");
        }

        if (passwordHash == null)
        {
            throw new ArgumentNullException(nameof(passwordHash), $"Parameter {nameof(passwordHash)} cannot be null.");
        }

        user.PasswordHash = passwordHash;
        return Task.CompletedTask;
    }

    public Task<string?> GetPasswordHashAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user), $"Parameter {nameof(user)} cannot be null.");
        }

        return Task.FromResult(user.PasswordHash);
    }

    public Task<bool> HasPasswordAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user), $"Parameter {nameof(user)} cannot be null.");
        }

        return Task.FromResult(!string.IsNullOrEmpty(user.PasswordHash));
    }

    public async Task<IList<Claim>> GetClaimsAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user), $"Parameter {nameof(user)} cannot be null.");
        }

        var connString = _configuration.GetSection("ConnectionStrings").GetValue<string>("DefaultConnection");
        await using var conn = new NpgsqlConnection(connString);
        await conn.OpenAsync();

        await using (var sqlConnection = conn)
        {
            var command = "SELECT * " +
                          $"FROM dbo.AspNetUserClaims " +
                          "WHERE UserId = @UserId;";

            return (
                    await sqlConnection.QueryAsync<IdentityUserClaim<string>>(command, new { UserId = user.Id })
                )
                .Select(e => new Claim(e.ClaimType, e.ClaimValue))
                .ToList();
        }
    }

    public async Task AddClaimsAsync(IdentityUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user), $"Parameter {nameof(user)} cannot be null.");
        }

        if (claims == null)
        {
            throw new ArgumentNullException(nameof(claims), $"Parameter {nameof(user)} cannot be null.");
        }

        var connString = _configuration.GetSection("ConnectionStrings").GetValue<string>("DefaultConnection");
        await using var conn = new NpgsqlConnection(connString);
        await conn.OpenAsync();

        await using (var sqlConnection = conn)
        {
            foreach (var claim in claims)
            {
                var insertClaimsCommand = $"INSERT INTO dbo.AspNetUserClaims (UserId, ClaimType, ClaimValue) " +
                                          "VALUES (@UserId, @ClaimType, @ClaimValue);";

                await sqlConnection.ExecuteAsync(insertClaimsCommand, new
                {
                    UserId = user.Id,
                    ClaimType = claim.Type,
                    ClaimValue = claim.Value
                });
            }
        }
    }

    public Task ReplaceClaimAsync(IdentityUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task RemoveClaimsAsync(IdentityUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<IList<IdentityUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public async Task AddLoginAsync(IdentityUser user, UserLoginInfo login, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (user == null)
        {
            throw new ArgumentNullException(nameof(user),
                $"Parameter {nameof(user)} cannot be null.");
        }

        if (login == null)
        {
            throw new ArgumentNullException(nameof(login),
                $"Parameter {nameof(login)} cannot be null.");
        }

        var connString = _configuration.GetSection("ConnectionStrings").GetValue<string>("DefaultConnection");
        await using var conn = new NpgsqlConnection(connString);
        await conn.OpenAsync();
        await using (var sqlConnection = conn)
        {
            var insertLoginsCommand =
                $"INSERT INTO dbo.AspNetUserLogins (LoginProvider, ProviderKey, ProviderDisplayName, UserId) " +
                "VALUES (@LoginProvider, @ProviderKey, @ProviderDisplayName, @UserId);";

            await sqlConnection.ExecuteAsync(insertLoginsCommand, new
            {
                login.LoginProvider,
                login.ProviderKey,
                login.ProviderDisplayName,
                UserId = user.Id
            });
        }
    }

    public async Task<IdentityUser?> FindByLoginAsync(
        string loginProvider,
        string providerKey,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (loginProvider == null)
        {
            throw new ArgumentNullException(nameof(loginProvider),
                $"Parameter {nameof(loginProvider)} cannot be null.");
        }

        var connString = _configuration.GetSection("ConnectionStrings").GetValue<string>("DefaultConnection");
        await using var conn = new NpgsqlConnection(connString);
        await conn.OpenAsync();

        await using (var sqlConnection = conn)
        {
            var command = "SELECT UserId " +
                          "FROM dbo.AspNetUserLogins " +
                          "WHERE LoginProvider = @LoginProvider AND ProviderKey = @ProviderKey;";

            var userId = await sqlConnection.QuerySingleOrDefaultAsync<string>(command, new
            {
                LoginProvider = loginProvider,
                ProviderKey = providerKey
            });

            if (userId == null)
            {
                return null;
            }

            command = "SELECT * " +
                      "FROM dbo.AspNetUsers " +
                      "WHERE Id = @Id;";

            return await sqlConnection.QuerySingleAsync<IdentityUser>(command, new { Id = userId });
        }
    }
    
    public Task RemoveLoginAsync(
        IdentityUser user,
        string loginProvider,
        string providerKey,
        CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public Task<IList<UserLoginInfo>> GetLoginsAsync(IdentityUser user, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}