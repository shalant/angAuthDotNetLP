using AngularAuthAPI.Context;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;

        public UserController(AppDbContext appDbContext)
        {
            _authContext = appDbContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] UserController userObj)
        {
            if(userObj == null)
                return BadRequest();

            var user = await _authContext.Users.FirstOrDefaultAsync(x => x.UserName == userObj.UserName);
            if(user == null)
                return NotFound(new {Message = "User not found"});
        }
    }
}
