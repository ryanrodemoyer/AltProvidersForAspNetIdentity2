using System;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

namespace Brade.AspNet.Identity.Dapper.Dapper
{
    public class DapperUserManager : UserManager<IdentityUser, string>
    {
        public DapperUserManager(IUserStore<IdentityUser, string> store) : base(store)
        {
        }

        public override async Task<IdentityResult> CreateAsync(IdentityUser user)
        {
            user.SecurityStamp = Guid.NewGuid().ToString();

            var result = await UserValidator.ValidateAsync(user);
            if (!result.Succeeded)
            {
                return result;
            }

            if (UserLockoutEnabledByDefault && SupportsUserLockout)
            {
                user.LockoutEnabled = true;
            }

            await Store.CreateAsync(user);

            return IdentityResult.Success;
        }

        public override async Task<IdentityResult> CreateAsync(IdentityUser user, string password)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }

            var result = await PasswordValidator.ValidateAsync(password);
            if (!result.Succeeded)
            {
                return result;
            }

            user.PasswordHash = PasswordHasher.HashPassword(password);
            user.SecurityStamp = Guid.NewGuid().ToString();

            return await CreateAsync(user);
        }
    }
}