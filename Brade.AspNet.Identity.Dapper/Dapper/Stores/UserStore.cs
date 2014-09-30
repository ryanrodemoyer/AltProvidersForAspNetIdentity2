using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using Dapper;
using Microsoft.AspNet.Identity;

namespace Brade.AspNet.Identity.Dapper
{
    public class DapperUserStore :
        IUserLoginStore<IdentityUser, string>,
        IUserClaimStore<IdentityUser, string>,
        IUserRoleStore<IdentityUser, string>,
        IUserPasswordStore<IdentityUser, string>,
        IUserSecurityStampStore<IdentityUser, string>,
        IQueryableUserStore<IdentityUser, string>,
        IUserEmailStore<IdentityUser, string>,
        IUserPhoneNumberStore<IdentityUser, string>,
        IUserTwoFactorStore<IdentityUser, string>,
        IUserLockoutStore<IdentityUser, string>
    {
        public DapperUserStore() { }

        public DapperUserStore(string connectionString)
        {
            ConnectionString = connectionString;
        }

        public string ConnectionString { get; private set; }

        public void Dispose()
        {
        }

        public async Task CreateAsync(IdentityUser user)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                var result = await FindByEmailAsync(user.Email);
                if (result == null)
                {
                    await db.Users.InsertAsync(user, removeId: false);
                }
            }
        }

        public async Task UpdateAsync(IdentityUser user)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                await db.Users.UpdateAsync(user.Id, user);
            }
        }

        public async Task DeleteAsync(IdentityUser user)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                await db.Users.DeleteAsync(user.Id);
            }
        }

        public async Task<IdentityUser> FindByIdAsync(string userId)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                return (await conn.QueryAsync<IdentityUser>(@"select * from Users where Id=@Id", new { Id = userId })).SingleOrDefault();
            }
        }

        public async Task<IdentityUser> FindByNameAsync(string userName)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                return (await conn.QueryAsync<IdentityUser>(@"select * from Users where UserName=@Name", new { Name = userName })).SingleOrDefault();
            }
        }

        public async Task AddLoginAsync(IdentityUser user, UserLoginInfo login)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                var instance = new IdentityUserLogin
                {
                    UserId = user.Id,
                    LoginProvider = login.LoginProvider,
                    ProviderKey = login.ProviderKey,
                };

                await db.UserLogins.InsertAsync(instance);
            }
        }

        public async Task RemoveLoginAsync(IdentityUser user, UserLoginInfo login)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                await conn.ExecuteAsync("delete from UserLogins where LoginProvider=@LoginProvider and ProviderKey=@ProviderKey", new { login.LoginProvider, login.ProviderKey }).ConfigureAwait(false);
            }
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(IdentityUser user)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                return (await conn
                    .QueryAsync<IdentityUserLogin>(@"select * from UserLogins where UserId=@UserId", new { UserId = user.Id }))
                    .Select(x => new UserLoginInfo(x.LoginProvider, x.ProviderKey))
                    .ToList();
            }
        }

        public async Task<IdentityUser> FindAsync(UserLoginInfo login)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                return (await conn
                    .QueryAsync<IdentityUser>(@"select U.* from Users U inner join UserLogins UL on U.Id=UL.UserId where UL.LoginProvider=@LoginProvider and UL.ProviderKey=@ProviderKey", new { login.LoginProvider, login.ProviderKey })).SingleOrDefault();
            }
        }

        public async Task<IList<Claim>> GetClaimsAsync(IdentityUser user)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                return (await conn
                    .QueryAsync<IdentityUserClaim>(@"select * from UserClaims where UserId=@UserId", new { UserId = user.Id }))
                    .Select(x => new Claim(x.ClaimType, x.ClaimValue))
                    .ToList();
            }
        }

        public async Task AddClaimAsync(IdentityUser user, Claim claim)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                var instance = new IdentityUserClaim
                {
                    UserId = user.Id,
                    ClaimType = claim.Type,
                    ClaimValue = claim.Value,
                };

                await db.UserClaims.InsertAsync(instance);
            }
        }

        public async Task RemoveClaimAsync(IdentityUser user, Claim claim)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                await conn.ExecuteAsync("delete from UserClaims where UserId=@UserId and ClaimValue=@ClaimValue and ClaimType=@ClaimType", new { UserId = user.Id, ClaimValue = claim.Value, ClaimType = claim.Type }).ConfigureAwait(false);
            }
        }

        public async Task AddToRoleAsync(IdentityUser user, string roleName)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                IdentityRole role = (await conn.QueryAsync<IdentityRole>(@"select * from Roles where Name=@RoleName", new { RoleName = roleName })).SingleOrDefault();
                if (role == null)
                {
                    throw new InvalidOperationException(string.Format("Role {0} not found.", roleName));
                }

                var instance = new IdentityUserRole
                {
                    RoleId = role.Id,
                    UserId = user.Id,
                };

                await db.UserRoles.InsertAsync(instance);
            }
        }

        public async Task RemoveFromRoleAsync(IdentityUser user, string roleName)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                IdentityRole role = (await conn.QueryAsync<IdentityRole>(@"select * from Roles where Name=@RoleName", new { RoleName = roleName })).SingleOrDefault();
                if (role == null)
                {
                    throw new InvalidOperationException(string.Format("Role {0} not found.", roleName));
                }

                await conn.ExecuteAsync("delete from UserRoles UR inner join Roles R on UR.RoleId=R.Id where UR.UserId=@UserId and R.RoleName=@RoleName", new { UserId = user.Id, RoleName = roleName }).ConfigureAwait(false);
            }
        }

        public async Task<IList<string>> GetRolesAsync(IdentityUser user)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                return (await conn
                    .QueryAsync<IdentityRole>(@"select R.* from UserRoles UR inner join Roles R on UR.RoleId=R.Id where UR.UserId=@UserId", new { UserId = user.Id }))
                    .Select(x => x.Name)
                    .ToList();
            }
        }

        public async Task<bool> IsInRoleAsync(IdentityUser user, string roleName)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                return (await conn
                    .QueryAsync<IdentityRole>(@"select R.* from UserRoles UR inner join Roles R on UR.RoleId=R.Id where UR.UserId=@UserId and R.Name=@RoleName", new { UserId = user.Id, RoleName = roleName }))
                    .Count() == 1;
            }
        }

        public async Task SetPasswordHashAsync(IdentityUser user, string passwordHash)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                IdentityUser u = await db.Users.GetAsync(user.Id);

                if (u != null)
                {
                    u.PasswordHash = passwordHash;

                    await db.Users.UpdateAsync(u.Id, u);
                }
            }
        }

        public async Task<string> GetPasswordHashAsync(IdentityUser user)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                return (await db.Users.GetAsync(user.Id)).PasswordHash;
            }
        }

        public async Task<bool> HasPasswordAsync(IdentityUser user)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                IdentityUser u = await db.Users.GetAsync(user.Id);

                return !string.IsNullOrEmpty(u.PasswordHash);
            }
        }

        public async Task SetSecurityStampAsync(IdentityUser user, string stamp)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                IdentityUser u = await db.Users.GetAsync(user.Id);
                if (u == null)
                {
                    throw new InvalidOperationException("Cannot find a user to set the security stamp.");
                }

                u.SecurityStamp = stamp;

                await db.Users.UpdateAsync(u.Id, u);
            }
        }

        public async Task<string> GetSecurityStampAsync(IdentityUser user)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                return (await db.Users.GetAsync(user.Id)).SecurityStamp;
            }
        }

        public IQueryable<IdentityUser> Users { get; private set; }

        public async Task SetEmailAsync(IdentityUser user, string email)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                IdentityUser u = await db.Users.GetAsync(user.Id);

                if (u != null)
                {
                    u.Email = email;

                    await db.Users.UpdateAsync(u.Id, u);
                }
            }
        }

        public async Task<string> GetEmailAsync(IdentityUser user)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                return (await db.Users.GetAsync(user.Id)).Email;
            }
        }

        public async Task<bool> GetEmailConfirmedAsync(IdentityUser user)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                return (await db.Users.GetAsync(user.Id)).EmailConfirmed;
            }
        }

        public async Task SetEmailConfirmedAsync(IdentityUser user, bool confirmed)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                IdentityUser u = await db.Users.GetAsync(user.Id);

                if (u != null)
                {
                    u.EmailConfirmed = confirmed;

                    await db.Users.UpdateAsync(u.Id, u);
                }
            }
        }

        public async Task<IdentityUser> FindByEmailAsync(string email)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                return (await conn.QueryAsync<IdentityUser>(@"select * from Users where Email=@Email", new { Email = email })).SingleOrDefault();
            }
        }

        public async Task SetPhoneNumberAsync(IdentityUser user, string phoneNumber)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                IdentityUser u = await db.Users.GetAsync(user.Id);

                if (u != null)
                {
                    u.PhoneNumber = phoneNumber;

                    await db.Users.UpdateAsync(u.Id, u);
                }
            }
        }

        public async Task<string> GetPhoneNumberAsync(IdentityUser user)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                return (await db.Users.GetAsync(user.Id)).PhoneNumber;
            }
        }

        public async Task<bool> GetPhoneNumberConfirmedAsync(IdentityUser user)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                return (await db.Users.GetAsync(user.Id)).PhoneNumberConfirmed;
            }
        }

        public async Task SetPhoneNumberConfirmedAsync(IdentityUser user, bool confirmed)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                IdentityUser u = await db.Users.GetAsync(user.Id);

                if (u != null)
                {
                    u.PhoneNumberConfirmed = confirmed;

                    await db.Users.UpdateAsync(u.Id, u);
                }
            }
        }

        public async Task SetTwoFactorEnabledAsync(IdentityUser user, bool enabled)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                IdentityUser u = await db.Users.GetAsync(user.Id);

                if (u != null)
                {
                    u.TwoFactorEnabled = enabled;

                    await db.Users.UpdateAsync(u.Id, u);
                }
            }
        }

        public async Task<bool> GetTwoFactorEnabledAsync(IdentityUser user)
        {
            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                return (await db.Users.GetAsync(user.Id)).TwoFactorEnabled;
            }
        }

        public async Task<DateTimeOffset> GetLockoutEndDateAsync(IdentityUser user)
        {
            return await GetUserField<DateTimeOffset>(user, "LockoutEndDateUtc");
        }

        public async Task SetLockoutEndDateAsync(IdentityUser user, DateTimeOffset lockoutEnd)
        {
            await SetUserField(user, "LockoutEndDateUtc", lockoutEnd);
        }

        public async Task<int> IncrementAccessFailedCountAsync(IdentityUser user)
        {
            //int result;

            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                IdentityUser u = await db.Users.GetAsync(user.Id);
                if (u == null)
                {
                    throw new ArgumentException("Cannot find user.");
                }

                int result = u.AccessFailedCount++;

                await db.Users.UpdateAsync(u.Id, u);

                return result;
            }

            //return result;
        }

        private async Task<T> GetUserField<T>(IdentityUser user, string fieldName)
        {
            T type = default(T);

            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                IdentityUser u = await db.Users.GetAsync(user.Id);
                if (u != null)
                {
                    var pi = user.GetType().GetProperties(BindingFlags.Instance | BindingFlags.Public).SingleOrDefault(x => x.Name == fieldName);
                    if (pi == null)
                    {
                        throw new ArgumentException(string.Format("Property name {0} does not exist for type IdentityUser.", fieldName));
                    }

                    type = (T)pi.GetValue(u);
                }
            }

            return type;
        }

        private async Task SetUserField(IdentityUser user, string fieldName, object value)
        {
            var pi = user.GetType().GetProperties(BindingFlags.Instance | BindingFlags.Public).SingleOrDefault(x => x.Name == fieldName);
            if (pi == null)
            {
                throw new ArgumentException(string.Format("Property name {0} does not exist for type IdentityUser.", fieldName));
            }

            using (SqlConnection conn = new SqlConnection(ConnectionString))
            {
                var db = IdentityDatabase.Init(conn, 2);

                IdentityUser u = await db.Users.GetAsync(user.Id);
                if (u != null)
                {
                    pi.SetValue(u, value);

                    await db.Users.UpdateAsync(u.Id, u);
                }
            }
        }

        public async Task ResetAccessFailedCountAsync(IdentityUser user)
        {
            await SetUserField(user, "AccessFailedCount", 0);
        }

        public async Task<int> GetAccessFailedCountAsync(IdentityUser user)
        {
            return await GetUserField<int>(user, "AccessFailedCount");
        }

        public async Task<bool> GetLockoutEnabledAsync(IdentityUser user)
        {
            return await GetUserField<bool>(user, "LockoutEnabled");
        }

        public async Task SetLockoutEnabledAsync(IdentityUser user, bool enabled)
        {
            await SetUserField(user, "LockoutEnabled", enabled);
        }
    }
}