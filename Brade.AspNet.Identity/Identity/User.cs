using System;
using Microsoft.AspNet.Identity;

namespace Brade.AspNet.Identity.Identity
{
    public class User<TUserKey> : IUser<TUserKey>
    {
        public string Email { get; set; }

        public bool EmailConfirmed { get; set; }
        public string PasswordHash { get; set; }
        public string SecurityStamp { get; set; }
        public string PhoneNumber { get; set; }
        public bool PhoneNumberConfirmed { get; set; }
        public bool TwoFactorEnabled { get; set; }
        public DateTime? LockoutEndDateUtc { get; set; }
        public bool LockoutEnabled { get; set; }
        public int AccessFailedCount { get; set; }

        public TUserKey Id { get; set; }
        public string UserName { get; set; }

        public User()
        {
            
        }
    }
}