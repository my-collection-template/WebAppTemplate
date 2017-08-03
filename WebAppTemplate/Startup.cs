using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(WebAppTemplate.Startup))]
namespace WebAppTemplate
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
