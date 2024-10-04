using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers
{
    [Produces("application/json")]
    [Route("api/bar")]
    //[Authorize(Roles = "customer")]
    public class BarController : Controller
    {

        [HttpPost]
        public async Task<IActionResult> Post([FromBody] Drink drink)
        {
            if (drink == null || string.IsNullOrEmpty(drink.DrinkName))
            {
                return BadRequest("Invalid data.");
            }

            return Ok($"Success! Received order for: {drink.DrinkName}");
        }
    }
}