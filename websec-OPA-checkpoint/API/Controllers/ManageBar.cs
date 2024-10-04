using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers
{
    [Produces("application/json")]
    [Route("api/managebar")]
    //[Authorize(Roles = "bartender")]
    public class ManageBarController : Controller
    {
        [HttpPost]
        public IActionResult Post([FromBody] Drink model)
        {
            if (model == null || string.IsNullOrEmpty(model.DrinkName))
            {
                return BadRequest("Invalid data.");
            }

            return Ok($"Success! Drink added: {model.DrinkName}");
        }
    }
}