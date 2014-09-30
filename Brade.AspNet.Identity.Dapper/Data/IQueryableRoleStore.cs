using Microsoft.AspNet.Identity;

namespace Brade.AspNet.Identity.Dapper.Data
{
    public interface IQueryableRoleStore<TRole> : IQueryableRoleStore<TRole, string> where TRole : IRole<string>
    {

    }
}
