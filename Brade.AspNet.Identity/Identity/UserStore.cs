using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Threading.Tasks;
using Brade.AspNet.Identity.Dapper.Data;
using Microsoft.AspNet.Identity;

namespace Brade.AspNet.Identity.Dapper
{
    public class UserStore<TUser> : 
        UserStore<TUser, IdentityRole, int, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>, 
        IUserStore<TUser>
            where TUser : IdentityUser
    {
        public UserStore() : base(new DataRepository())
        {
        }

        public UserStore(IDataRepository repository) : base(repository)
        {
        }
    }

    public class UserStore<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim> :
        IUserLoginStore<TUser, TKey>, 
        IUserClaimStore<TUser, TKey>, 
        IUserRoleStore<TUser, TKey>, 
        IUserPasswordStore<TUser, TKey>, 
        IUserSecurityStampStore<TUser, TKey>, 
        IQueryableUserStore<TUser, TKey>, 
        IUserEmailStore<TUser, TKey>, 
        IUserPhoneNumberStore<TUser, TKey>, 
        IUserTwoFactorStore<TUser, TKey>, 
        IUserLockoutStore<TUser, TKey>
            where TUser : IdentityUser<TKey, TUserLogin, TUserRole, TUserClaim> 
            where TRole : IdentityRole<TKey, TUserRole> 
            where TKey : IEquatable<TKey> 
            where TUserLogin : IdentityUserLogin<TKey>, new() 
            where TUserRole : IdentityUserRole<TKey>, new() 
            where TUserClaim : IdentityUserClaim<TKey>, new()
  {
    private readonly IDbSet<TUserLogin> _logins;
    private readonly EntityStore<TRole> _roleStore;
    private readonly IDbSet<TUserClaim> _userClaims;
    private readonly IDbSet<TUserRole> _userRoles;
    private bool _disposed;
    private EntityStore<TUser> _userStore;

    /// <summary>
    /// Context for the store
    /// 
    /// </summary>
    public DbContext Context { get; private set; }

    /// <summary>
    /// If true will call dispose on the DbContext during Dispose
    /// 
    /// </summary>
    public bool DisposeContext { get; set; }

    /// <summary>
    /// If true will call SaveChanges after Create/Update/Delete
    /// 
    /// </summary>
    public bool AutoSaveChanges { get; set; }

    /// <summary>
    /// Returns an IQueryable of users
    /// 
    /// </summary>
    public IQueryable<TUser> Users
    {
      get
      {
        return this._userStore.EntitySet;
      }
    }

        private readonly IDataRepository _repository;

        public UserStore(IDataRepository repository)
        {
            _repository = repository;
        }

    public UserStore(DbContext context)
    {
      if (context == null)
        throw new ArgumentNullException("context");
      this.Context = context;
      this.AutoSaveChanges = true;
      this._userStore = new EntityStore<TUser>(context);
      this._roleStore = new EntityStore<TRole>(context);
      this._logins = (IDbSet<TUserLogin>) this.Context.Set<TUserLogin>();
      this._userClaims = (IDbSet<TUserClaim>) this.Context.Set<TUserClaim>();
      this._userRoles = (IDbSet<TUserRole>) this.Context.Set<TUserRole>();
    }

    /// <summary>
    /// Return the claims for a user
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public virtual Task<IList<Claim>> GetClaimsAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      else
        return Task.FromResult<IList<Claim>>((IList<Claim>) Enumerable.ToList<Claim>(Enumerable.Select<TUserClaim, Claim>((IEnumerable<TUserClaim>) user.Claims, (Func<TUserClaim, Claim>) (c => new Claim(c.ClaimType, c.ClaimValue)))));
    }

    /// <summary>
    /// Add a claim to a user
    /// 
    /// </summary>
    /// <param name="user"/><param name="claim"/>
    /// <returns/>
    public virtual Task AddClaimAsync(TUser user, Claim claim)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      if (claim == null)
        throw new ArgumentNullException("claim");
      ICollection<TUserClaim> claims = user.Claims;
      TUserClaim instance = Activator.CreateInstance<TUserClaim>();
      instance.UserId = user.Id;
      instance.ClaimType = claim.Type;
      instance.ClaimValue = claim.Value;
      TUserClaim userClaim = instance;
      claims.Add(userClaim);
      return (Task) Task.FromResult<int>(0);
    }

    /// <summary>
    /// Remove a claim from a user
    /// 
    /// </summary>
    /// <param name="user"/><param name="claim"/>
    /// <returns/>
    public virtual Task RemoveClaimAsync(TUser user, Claim claim)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      if (claim == null)
        throw new ArgumentNullException("claim");
      foreach (TUserClaim userClaim in Enumerable.ToList<TUserClaim>(Enumerable.Where<TUserClaim>((IEnumerable<TUserClaim>) user.Claims, (Func<TUserClaim, bool>) (uc =>
      {
        if (uc.ClaimValue == claim.Value)
          return uc.ClaimType == claim.Type;
        else
          return false;
      }))))
        user.Claims.Remove(userClaim);
      IDbSet<TUserClaim> idbSet = this._userClaims;
      Expression<Func<TUserClaim, bool>> predicate = (Expression<Func<TUserClaim, bool>>) (uc => uc.UserId.Equals(user.Id) && uc.ClaimValue == claim.Value && uc.ClaimType == claim.Type);
      foreach (TUserClaim userClaim in (IEnumerable<TUserClaim>) Queryable.Where<TUserClaim>((IQueryable<TUserClaim>) idbSet, predicate))
        this._userClaims.Remove(userClaim);
      return (Task) Task.FromResult<int>(0);
    }

    /// <summary>
    /// Returns whether the user email is confirmed
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public Task<bool> GetEmailConfirmedAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      else
        return Task.FromResult<bool>(user.EmailConfirmed);
    }

    /// <summary>
    /// Set IsConfirmed on the user
    /// 
    /// </summary>
    /// <param name="user"/><param name="confirmed"/>
    /// <returns/>
    public Task SetEmailConfirmedAsync(TUser user, bool confirmed)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      user.EmailConfirmed = confirmed;
      return (Task) Task.FromResult<int>(0);
    }

    /// <summary>
    /// Set the user email
    /// 
    /// </summary>
    /// <param name="user"/><param name="email"/>
    /// <returns/>
    public Task SetEmailAsync(TUser user, string email)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      user.Email = email;
      return (Task) Task.FromResult<int>(0);
    }

    /// <summary>
    /// Get the user's email
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public Task<string> GetEmailAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      else
        return Task.FromResult<string>(user.Email);
    }

    /// <summary>
    /// Find a user by email
    /// 
    /// </summary>
    /// <param name="email"/>
    /// <returns/>
    public Task<TUser> FindByEmailAsync(string email)
    {
      this.ThrowIfDisposed();
      return this.GetUserAggregateAsync((Expression<Func<TUser, bool>>) (u => u.Email.ToUpper() == email.ToUpper()));
    }

    /// <summary>
    /// Returns the DateTimeOffset that represents the end of a user's lockout, any time in the past should be considered
    ///                 not locked out.
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      else
        return Task.FromResult<DateTimeOffset>(user.LockoutEndDateUtc.HasValue ? new DateTimeOffset(DateTime.SpecifyKind(user.LockoutEndDateUtc.Value, DateTimeKind.Utc)) : new DateTimeOffset());
    }

    /// <summary>
    /// Locks a user out until the specified end date (set to a past date, to unlock a user)
    /// 
    /// </summary>
    /// <param name="user"/><param name="lockoutEnd"/>
    /// <returns/>
    public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      user.LockoutEndDateUtc = lockoutEnd == DateTimeOffset.MinValue ? new DateTime?() : new DateTime?(lockoutEnd.UtcDateTime);
      return (Task) Task.FromResult<int>(0);
    }

    /// <summary>
    /// Used to record when an attempt to access the user has failed
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public Task<int> IncrementAccessFailedCountAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      ++user.AccessFailedCount;
      return Task.FromResult<int>(user.AccessFailedCount);
    }

    /// <summary>
    /// Used to reset the account access count, typically after the account is successfully accessed
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public Task ResetAccessFailedCountAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      user.AccessFailedCount = 0;
      return (Task) Task.FromResult<int>(0);
    }

    /// <summary>
    /// Returns the current number of failed access attempts.  This number usually will be reset whenever the password is
    ///                 verified or the account is locked out.
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public Task<int> GetAccessFailedCountAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      else
        return Task.FromResult<int>(user.AccessFailedCount);
    }

    /// <summary>
    /// Returns whether the user can be locked out.
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public Task<bool> GetLockoutEnabledAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      else
        return Task.FromResult<bool>(user.LockoutEnabled);
    }

    /// <summary>
    /// Sets whether the user can be locked out.
    /// 
    /// </summary>
    /// <param name="user"/><param name="enabled"/>
    /// <returns/>
    public Task SetLockoutEnabledAsync(TUser user, bool enabled)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      user.LockoutEnabled = enabled;
      return (Task) Task.FromResult<int>(0);
    }

    /// <summary>
    /// Find a user by id
    /// 
    /// </summary>
    /// <param name="userId"/>
    /// <returns/>
    public virtual Task<TUser> FindByIdAsync(TKey userId)
    {
      this.ThrowIfDisposed();
      return this.GetUserAggregateAsync((Expression<Func<TUser, bool>>) (u => u.Id.Equals(userId)));
    }

    /// <summary>
    /// Find a user by name
    /// 
    /// </summary>
    /// <param name="userName"/>
    /// <returns/>
    public virtual Task<TUser> FindByNameAsync(string userName)
    {
      this.ThrowIfDisposed();
      return this.GetUserAggregateAsync((Expression<Func<TUser, bool>>) (u => u.UserName.ToUpper() == userName.ToUpper()));
    }

    /// <summary>
    /// Insert an entity
    /// 
    /// </summary>
    /// <param name="user"/>
    public virtual async Task CreateAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      this._userStore.Create(user);
      await TaskExtensions.WithCurrentCulture(this.SaveChanges());
    }

    /// <summary>
    /// Mark an entity for deletion
    /// 
    /// </summary>
    /// <param name="user"/>
    public virtual async Task DeleteAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      this._userStore.Delete(user);
      await TaskExtensions.WithCurrentCulture(this.SaveChanges());
    }

    /// <summary>
    /// Update an entity
    /// 
    /// </summary>
    /// <param name="user"/>
    public virtual async Task UpdateAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      this._userStore.Update(user);
      await TaskExtensions.WithCurrentCulture(this.SaveChanges());
    }

    /// <summary>
    /// Dispose the store
    /// 
    /// </summary>
    public void Dispose()
    {
      this.Dispose(true);
      GC.SuppressFinalize((object) this);
    }

    public virtual async Task<TUser> FindAsync(UserLoginInfo login)
    {
      // ISSUE: object of a compiler-generated type is created
      // ISSUE: variable of a compiler-generated type
      UserStore<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim>.\u003C\u003Ec__DisplayClass15 cDisplayClass15 = new UserStore<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim>.\u003C\u003Ec__DisplayClass15();
      this.ThrowIfDisposed();
      if (login == null)
        throw new ArgumentNullException("login");
      // ISSUE: reference to a compiler-generated field
      cDisplayClass15.provider = login.get_LoginProvider();
      // ISSUE: reference to a compiler-generated field
      cDisplayClass15.key = login.get_ProviderKey();
      // ISSUE: reference to a compiler-generated field
      // ISSUE: reference to a compiler-generated field
      // ISSUE: reference to a compiler-generated field
      cDisplayClass15.userLogin = await ((Task<TUserLogin>) QueryableExtensions.FirstOrDefaultAsync<TUserLogin>((IQueryable<M0>) this._logins, (Expression<Func<M0, bool>>) (l => l.LoginProvider == cDisplayClass15.provider && l.ProviderKey == cDisplayClass15.key)));
      TUser user;
      // ISSUE: reference to a compiler-generated field
      if ((object) cDisplayClass15.userLogin != null)
      {
        // ISSUE: reference to a compiler-generated field
        user = await this.GetUserAggregateAsync((Expression<Func<TUser, bool>>) (u => u.Id.Equals(cDisplayClass15.userLogin.UserId)));
      }
      else
        user = default (TUser);
      return user;
    }

    public virtual Task AddLoginAsync(TUser user, UserLoginInfo login)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      if (login == null)
        throw new ArgumentNullException("login");
      ICollection<TUserLogin> logins = user.Logins;
      TUserLogin instance = Activator.CreateInstance<TUserLogin>();
      instance.UserId = user.Id;
      instance.ProviderKey = login.get_ProviderKey();
      instance.LoginProvider = login.get_LoginProvider();
      TUserLogin userLogin = instance;
      logins.Add(userLogin);
      return (Task) Task.FromResult<int>(0);
    }

    public virtual Task RemoveLoginAsync(TUser user, UserLoginInfo login)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      if (login == null)
        throw new ArgumentNullException("login");
      string provider = login.get_LoginProvider();
      string key = login.get_ProviderKey();
      TUserLogin userLogin = Enumerable.SingleOrDefault<TUserLogin>((IEnumerable<TUserLogin>) user.Logins, (Func<TUserLogin, bool>) (l =>
      {
        if (l.LoginProvider == provider)
          return l.ProviderKey == key;
        else
          return false;
      }));
      if ((object) userLogin != null)
        user.Logins.Remove(userLogin);
      return (Task) Task.FromResult<int>(0);
    }

    /// <summary>
    /// Get the logins for a user
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public virtual Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      else
        return Task.FromResult<IList<UserLoginInfo>>((IList<UserLoginInfo>) Enumerable.ToList<UserLoginInfo>(Enumerable.Select<TUserLogin, UserLoginInfo>((IEnumerable<TUserLogin>) user.Logins, (Func<TUserLogin, UserLoginInfo>) (l => new UserLoginInfo(l.LoginProvider, l.ProviderKey)))));
    }

    /// <summary>
    /// Set the password hash for a user
    /// 
    /// </summary>
    /// <param name="user"/><param name="passwordHash"/>
    /// <returns/>
    public Task SetPasswordHashAsync(TUser user, string passwordHash)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      user.PasswordHash = passwordHash;
      return (Task) Task.FromResult<int>(0);
    }

    /// <summary>
    /// Get the password hash for a user
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public Task<string> GetPasswordHashAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      else
        return Task.FromResult<string>(user.PasswordHash);
    }

    /// <summary>
    /// Returns true if the user has a password set
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public Task<bool> HasPasswordAsync(TUser user)
    {
      return Task.FromResult<bool>(user.PasswordHash != null);
    }

    /// <summary>
    /// Set the user's phone number
    /// 
    /// </summary>
    /// <param name="user"/><param name="phoneNumber"/>
    /// <returns/>
    public Task SetPhoneNumberAsync(TUser user, string phoneNumber)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      user.PhoneNumber = phoneNumber;
      return (Task) Task.FromResult<int>(0);
    }

    /// <summary>
    /// Get a user's phone number
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public Task<string> GetPhoneNumberAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      else
        return Task.FromResult<string>(user.PhoneNumber);
    }

    /// <summary>
    /// Returns whether the user phoneNumber is confirmed
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      else
        return Task.FromResult<bool>(user.PhoneNumberConfirmed);
    }

    /// <summary>
    /// Set PhoneNumberConfirmed on the user
    /// 
    /// </summary>
    /// <param name="user"/><param name="confirmed"/>
    /// <returns/>
    public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      user.PhoneNumberConfirmed = confirmed;
      return (Task) Task.FromResult<int>(0);
    }

    /// <summary>
    /// Add a user to a role
    /// 
    /// </summary>
    /// <param name="user"/><param name="roleName"/>
    /// <returns/>
    public virtual Task AddToRoleAsync(TUser user, string roleName)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      if (string.IsNullOrWhiteSpace(roleName))
        throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, "roleName");
      TRole role = Queryable.SingleOrDefault<TRole>((IQueryable<TRole>) this._roleStore.DbEntitySet, (Expression<Func<TRole, bool>>) (r => r.Name.ToUpper() == roleName.ToUpper()));
      if ((object) role == null)
      {
        throw new InvalidOperationException(string.Format((IFormatProvider) CultureInfo.CurrentCulture, IdentityResources.RoleNotFound, new object[1]
        {
          (object) roleName
        }));
      }
      else
      {
        TUserRole instance = Activator.CreateInstance<TUserRole>();
        instance.UserId = user.Id;
        instance.RoleId = role.Id;
        this._userRoles.Add(instance);
        return (Task) Task.FromResult<int>(0);
      }
    }

    /// <summary>
    /// Remove a user from a role
    /// 
    /// </summary>
    /// <param name="user"/><param name="roleName"/>
    /// <returns/>
    public virtual Task RemoveFromRoleAsync(TUser user, string roleName)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      if (string.IsNullOrWhiteSpace(roleName))
        throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, "roleName");
      TRole role = Queryable.SingleOrDefault<TRole>((IQueryable<TRole>) this._roleStore.DbEntitySet, (Expression<Func<TRole, bool>>) (r => r.Name.ToUpper() == roleName.ToUpper()));
      if ((object) role != null)
      {
        TKey roleId = role.Id;
        TKey userId = user.Id;
        TUserRole userRole = Queryable.FirstOrDefault<TUserRole>((IQueryable<TUserRole>) this._userRoles, (Expression<Func<TUserRole, bool>>) (r => roleId.Equals(r.RoleId) && r.UserId.Equals(userId)));
        if ((object) userRole != null)
          this._userRoles.Remove(userRole);
      }
      return (Task) Task.FromResult<int>(0);
    }

    /// <summary>
    /// Get the names of the roles a user is a member of
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public virtual Task<IList<string>> GetRolesAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      else
        return Task.FromResult<IList<string>>((IList<string>) Enumerable.ToList<string>(Enumerable.Join<TUserRole, TRole, TKey, string>((IEnumerable<TUserRole>) user.Roles, (IEnumerable<TRole>) this._roleStore.DbEntitySet, (Func<TUserRole, TKey>) (userRoles => userRoles.RoleId), (Func<TRole, TKey>) (roles => roles.Id), (Func<TUserRole, TRole, string>) ((userRoles, roles) => roles.Name))));
    }

    /// <summary>
    /// Returns true if the user is in the named role
    /// 
    /// </summary>
    /// <param name="user"/><param name="roleName"/>
    /// <returns/>
    public virtual Task<bool> IsInRoleAsync(TUser user, string roleName)
    {
      // ISSUE: object of a compiler-generated type is created
      // ISSUE: variable of a compiler-generated type
      UserStore<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim>.\u003C\u003Ec__DisplayClass31 cDisplayClass31 = new UserStore<TUser, TRole, TKey, TUserLogin, TUserRole, TUserClaim>.\u003C\u003Ec__DisplayClass31();
      // ISSUE: reference to a compiler-generated field
      cDisplayClass31.user = user;
      // ISSUE: reference to a compiler-generated field
      cDisplayClass31.roleName = roleName;
      this.ThrowIfDisposed();
      // ISSUE: reference to a compiler-generated field
      if ((object) cDisplayClass31.user == null)
        throw new ArgumentNullException("user");
      // ISSUE: reference to a compiler-generated field
      if (string.IsNullOrWhiteSpace(cDisplayClass31.roleName))
        throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, "roleName");
      bool result = false;
      // ISSUE: reference to a compiler-generated field
      // ISSUE: reference to a compiler-generated field
      cDisplayClass31.role = Queryable.SingleOrDefault<TRole>((IQueryable<TRole>) this._roleStore.DbEntitySet, (Expression<Func<TRole, bool>>) (r => r.Name.ToUpper() == cDisplayClass31.roleName.ToUpper()));
      // ISSUE: reference to a compiler-generated field
      if ((object) cDisplayClass31.role != null)
      {
        // ISSUE: reference to a compiler-generated field
        // ISSUE: reference to a compiler-generated method
        result = Enumerable.Any<TUserRole>((IEnumerable<TUserRole>) cDisplayClass31.role.Users, new Func<TUserRole, bool>(cDisplayClass31.\u003CIsInRoleAsync\u003Eb__2f));
      }
      return Task.FromResult<bool>(result);
    }

    /// <summary>
    /// Set the security stamp for the user
    /// 
    /// </summary>
    /// <param name="user"/><param name="stamp"/>
    /// <returns/>
    public Task SetSecurityStampAsync(TUser user, string stamp)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      user.SecurityStamp = stamp;
      return (Task) Task.FromResult<int>(0);
    }

    /// <summary>
    /// Get the security stamp for a user
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public Task<string> GetSecurityStampAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      else
        return Task.FromResult<string>(user.SecurityStamp);
    }

    /// <summary>
    /// Set whether two factor authentication is enabled for the user
    /// 
    /// </summary>
    /// <param name="user"/><param name="enabled"/>
    /// <returns/>
    public Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      user.TwoFactorEnabled = enabled;
      return (Task) Task.FromResult<int>(0);
    }

    /// <summary>
    /// Gets whether two factor authentication is enabled for the user
    /// 
    /// </summary>
    /// <param name="user"/>
    /// <returns/>
    public Task<bool> GetTwoFactorEnabledAsync(TUser user)
    {
      this.ThrowIfDisposed();
      if ((object) user == null)
        throw new ArgumentNullException("user");
      else
        return Task.FromResult<bool>(user.TwoFactorEnabled);
    }

    private async Task SaveChanges()
    {
      if (this.AutoSaveChanges)
      {
        int num = await ((TaskExtensions.CultureAwaiter<int>) TaskExtensions.WithCurrentCulture<int>((Task<M0>) this.Context.SaveChangesAsync()));
      }
    }

    /// <summary>
    /// Used to attach child entities to the User aggregate, i.e. Roles, Logins, and Claims
    /// 
    /// </summary>
    /// <param name="filter"/>
    /// <returns/>
    protected virtual Task<TUser> GetUserAggregateAsync(Expression<Func<TUser, bool>> filter)
    {
      return (Task<TUser>) QueryableExtensions.FirstOrDefaultAsync<TUser>(QueryableExtensions.Include<TUser, ICollection<TUserLogin>>(QueryableExtensions.Include<TUser, ICollection<TUserClaim>>(QueryableExtensions.Include<TUser, ICollection<TUserRole>>((IQueryable<M0>) this.Users, (Expression<Func<M0, M1>>) (u => u.Roles)), (Expression<Func<M0, M1>>) (u => u.Claims)), (Expression<Func<M0, M1>>) (u => u.Logins)), (Expression<Func<M0, bool>>) filter);
    }

    private void ThrowIfDisposed()
    {
      if (this._disposed)
        throw new ObjectDisposedException(this.GetType().Name);
    }

    /// <summary>
    /// If disposing, calls dispose on the Context.  Always nulls out the Context
    /// 
    /// </summary>
    /// <param name="disposing"/>
    protected virtual void Dispose(bool disposing)
    {
      if (this.DisposeContext && disposing && this.Context != null)
        this.Context.Dispose();
      this._disposed = true;
      this.Context = (DbContext) null;
      this._userStore = (EntityStore<TUser>) null;
    }
  }
}