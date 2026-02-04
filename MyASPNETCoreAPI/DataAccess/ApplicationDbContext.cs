using Microsoft.EntityFrameworkCore;
using MyASPNETCoreAPI.Models;

namespace MyASPNETCoreAPI.DataAccess
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<Employee> Employee { get; set; } = null!;
    }
}