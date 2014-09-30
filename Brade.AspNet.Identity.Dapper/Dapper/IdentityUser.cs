using System;
using Brade.AspNet.Identity.Identity;

namespace Brade.AspNet.Identity.Dapper
{
    public class IdentityUser : User<string>
    {
        public IdentityUser()
        {
            Id = Guid.NewGuid().ToString();
        }
    }
}