using OpenIdClientForNet.App_Start;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace OpenIdClientForNet
{
    public class MvcApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            BundleConfig.RegisterBundles(BundleTable.Bundles);

            // OWIN başlatma
            ConfigureAuth();
        }
        public void ConfigureAuth()
        {
            // OWIN başlangıç sınıfını başlat
            var startup = new Startup();
            startup.Configuration(new Microsoft.Owin.Builder.AppBuilder());
        }
    }
}
