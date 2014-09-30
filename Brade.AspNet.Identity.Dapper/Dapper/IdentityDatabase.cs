using Dapper;

namespace Brade.AspNet.Identity.Dapper
{
    public class IdentityDatabase : Database<IdentityDatabase>
    {
        public class StringTable<T> : Table<T, string>
        {
            public StringTable(Database<IdentityDatabase> database, string likelyTableName) : base(database, likelyTableName)
            {
            }
        }

        public Table<IdentityRole, string> Roles { get; set; }

        public Table<IdentityUser, string> Users { get; set; }

        public Table<IdentityUserRole> UserRoles { get; set; }

        public Table<IdentityUserLogin> UserLogins { get; set; }

        public Table<IdentityUserClaim> UserClaims { get; set; } 
    }
}