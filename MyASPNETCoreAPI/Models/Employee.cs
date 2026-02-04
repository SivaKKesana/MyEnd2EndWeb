using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace MyASPNETCoreAPI.Models
{
    public class Employee
    {
        [Key]
        [Required]
        [Column("emp_id")]
        [StringLength(50)]
        [Display(Name = "Employee Id")]
        public string EmpId { get; set; } = null!;

        [Required]
        [Column("fname")]
        [StringLength(100)]
        [Display(Name = "First Name")]
        public string FirstName { get; set; } = null!;

        [Column("minit")]
        [StringLength(1, ErrorMessage = "Middle initial must be a single character.")]
        [Display(Name = "Middle Initial")]
        public string? MiddleInitial { get; set; }

        [Required]
        [Column("lname")]
        [StringLength(100)]
        [Display(Name = "Last Name")]
        public string LastName { get; set; } = null!;
    }
}