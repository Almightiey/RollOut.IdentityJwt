using Microsoft.EntityFrameworkCore;
using RollOut.IdentityJwt.Models;

public class AuthDbContext : DbContext, IDbContext
{
    public DbSet<User> Users { get; set; }
    public AuthDbContext(DbContextOptions<AuthDbContext> options)
        : base(options) { }

}
