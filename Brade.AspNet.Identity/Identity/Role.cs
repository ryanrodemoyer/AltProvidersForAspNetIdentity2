using Microsoft.AspNet.Identity;

namespace Brade.AspNet.Identity.Identity
{
    public class Role<TRoleKey> : IRole<TRoleKey>
    {
        public TRoleKey Id { get; set; }

        public string Name { get; set; }

        public Role() { }
    }
}