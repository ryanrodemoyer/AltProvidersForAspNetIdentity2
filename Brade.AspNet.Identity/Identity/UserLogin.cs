namespace Brade.AspNet.Identity.Identity
{
    public class UserLogin<TUserKey, TUserLoginKey>
    {
        public TUserLoginKey Id { get; set; }
        public TUserKey UserId { get; set; }  
        public string LoginProvider { get; set; }
        public string ProviderKey { get; set; } 
    }
}