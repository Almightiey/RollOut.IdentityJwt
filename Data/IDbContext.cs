using Microsoft.EntityFrameworkCore;
using RollOut.IdentityJwt.Models;

public interface IDbContext
{
    DbSet<User> Users { get; set; }
    Task<int> SaveChangesAsync(CancellationToken cancellationToken);
}