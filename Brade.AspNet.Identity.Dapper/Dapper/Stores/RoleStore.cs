using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;
using Brade.AspNet.Identity.Dapper;
using Brade.AspNet.Identity.Dapper.Data;
using Dapper;

namespace Brade.AspNet.Identity
{
    public class RoleStore : IQueryableRoleStore<IdentityRole>
    {
        public void Dispose()
        {
            throw new System.NotImplementedException();
        }

        public async Task CreateAsync(IdentityRole role)
        {
            using (SqlConnection conn = new SqlConnection())
            {
                var db = IdentityDatabase.Init(conn, 2);

                await db.Roles.InsertAsync(role);
            }
        }

        public async Task UpdateAsync(IdentityRole role)
        {
            using (SqlConnection conn = new SqlConnection())
            {
                var db = IdentityDatabase.Init(conn, 2);

                await db.Roles.UpdateAsync(role.Id, role);
            }
        }

        public async Task DeleteAsync(IdentityRole role)
        {
            using (SqlConnection conn = new SqlConnection())
            {
                var db = IdentityDatabase.Init(conn, 2);

                await db.Roles.DeleteAsync(role.Id);
            }
        }

        public async Task<IdentityRole> FindByIdAsync(string roleId)
        {
            using (SqlConnection conn = new SqlConnection())
            {
                return (await conn.QueryAsync<IdentityRole>(@"select * from Roles where Id=@Id", new { Id = roleId })).SingleOrDefault();
            }
        }

        public async Task<IdentityRole> FindByNameAsync(string roleName)
        {
            using (SqlConnection conn = new SqlConnection())
            {
                return (await conn.QueryAsync<IdentityRole>(@"select * from Roles where Name=@Name", new { Name = roleName })).SingleOrDefault();
            }
        }

        private IQueryable<IdentityRole> _roles;
        public IQueryable<IdentityRole> Roles
        {
            get
            {
                using (SqlConnection conn = new SqlConnection())
                {
                    return (_roles = conn.Query<IdentityRole>(@"select * from Roles").AsQueryable());
                }
            }
        }
    }
}