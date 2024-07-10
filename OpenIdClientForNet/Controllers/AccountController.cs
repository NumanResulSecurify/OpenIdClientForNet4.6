using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace OpenIdClientForNet.Controllers
{
    public class AccountController : Controller
    {
        // Giriş yapma işlemi
        public void SignIn()
        {
            if (!Request.IsAuthenticated)
            {
                HttpContext.GetOwinContext().Authentication.Challenge(
                    new Microsoft.Owin.Security.AuthenticationProperties { RedirectUri = "/" },
                    OpenIdConnectAuthenticationDefaults.AuthenticationType);
            }
        }

        // Çıkış yapma işlem    
        public ActionResult Logout()
        {
            var authentication = HttpContext.GetOwinContext().Authentication;
            var idToken = GetToken("id_token");

            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action("Index", "Home")
            };

            properties.Dictionary["id_token_hint"] = idToken;
            properties.Dictionary["post_logout_redirect_uri"] = Url.Action("Index", "Home", null, Request.Url.Scheme);

            authentication.SignOut(properties, OpenIdConnectAuthenticationDefaults.AuthenticationType, CookieAuthenticationDefaults.AuthenticationType);
            return new EmptyResult();
        }

        private string GetToken(string tokenType)
        {
            var result = HttpContext.GetOwinContext().Authentication.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationType).Result;
            return result?.Properties?.Dictionary.ContainsKey(tokenType) == true ? result.Properties.Dictionary[tokenType] : null;
        }

    }
}