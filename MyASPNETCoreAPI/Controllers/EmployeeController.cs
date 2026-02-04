using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using MyASPNETCoreAPI.DataAccess;
using MyASPNETCoreAPI.Models;
using Microsoft.Data.SqlClient;

namespace MyASPNETCoreAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class EmployeeController : ControllerBase
    {
        private readonly ApplicationDbContext _db;
        private readonly ILogger<EmployeeController> _logger;

        public EmployeeController(ApplicationDbContext db, ILogger<EmployeeController> logger)
        {
            _db = db;
            _logger = logger;
        }

        // GET: api/employee
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Employee>>> Get()
        {
            return Ok(await _db.Employee.AsNoTracking().ToListAsync());
        }

        // GET: api/employee/{emp_id}
        [HttpGet("{emp_id}")]
        public async Task<ActionResult<Employee>> GetById(string emp_id)
        {
            var employee = await _db.Employee.FindAsync(emp_id);
            if (employee == null) return NotFound();
            return Ok(employee);
        }

        // POST: api/employee
        [HttpPost]
        public async Task<IActionResult> Create([FromBody] Employee employee)
        {
            if (!ModelState.IsValid) return BadRequest(ModelState);

            // Example quick server-side validation: adjust to match your DB constraint
            if (string.IsNullOrWhiteSpace(employee.EmpId) || employee.EmpId.Length > 50)
            {
                ModelState.AddModelError(nameof(employee.EmpId), "EmpId is required and must be <= 50 chars.");
                return BadRequest(ModelState);
            }

            _db.Employee.Add(employee);
            try
            {
                await _db.SaveChangesAsync();
            }
            catch (DbUpdateException dbEx)
            {
                var sqlEx = dbEx.GetBaseException() as SqlException;
                _logger.LogError(dbEx, "Error saving Employee. SqlMessage: {SqlMessage}", sqlEx?.Message ?? dbEx.Message);

                // In dev return helpful message; in production return generic error
                return StatusCode(500, new
                {
                    Error = "Database error while saving employee.",
                    Detail = sqlEx?.Message ?? dbEx.Message
                });
            }

            return CreatedAtAction(nameof(GetById), new { emp_id = employee.EmpId }, employee);
        }
    }
}
