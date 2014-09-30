using Brade.AspNet.Identity.Identity;

namespace Brade.AspNet.Identity.Dapper
{
    public class IdentityUserRole : UserRole<int, string, string>
    {
        public IdentityUserRole() { }
    }
}