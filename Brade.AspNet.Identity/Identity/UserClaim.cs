namespace Brade.AspNet.Identity.Identity
{
    public class UserClaim<TUserKey, TClaimKey>
    {
        public TClaimKey Id { get; set; }
        public TUserKey UserId { get; set; }
        public string ClaimType { get; set; }
        public string ClaimValue { get; set; }
    }
}