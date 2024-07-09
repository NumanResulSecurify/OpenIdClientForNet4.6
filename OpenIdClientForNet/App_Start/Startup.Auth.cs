using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System.Configuration;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.Owin.Security;
using System.Net.Http;
using System.Security.Claims;
using System;
using IdentityModel.Client;
using static IdentityModel.ClaimComparer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using OpenIdClientForNet.Helpers;
using System.Collections.Generic;
using Newtonsoft.Json;

[assembly: OwinStartup(typeof(OpenIdClientForNet.App_Start.Startup))]
namespace OpenIdClientForNet.App_Start
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            // Tanımlanan ayarları al
            var clientId = ConfigurationManager.AppSettings["ClientId"];
            var clientSecret = ConfigurationManager.AppSettings["ClientSecret"];
            var authority = ConfigurationManager.AppSettings["Authority"];
            var redirectUri = ConfigurationManager.AppSettings["RedirectUri"];
            var postLogoutRedirectUri = ConfigurationManager.AppSettings["PostLogoutRedirectUri"];
            
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = false, // Anahtar imzasını doğrulama
                ValidateIssuer = false, // Issuer'ı doğrulama
                ValidateAudience = false, // Audience'ı doğrulama
                ValidateLifetime = true, // Token'ın geçerliliğini doğrulama
                SignatureValidator = (token, parameters) => new JwtSecurityToken(token), // İmza doğrulayıcıyı devre dışı bırakma
            };
            // Çerez tabanlı kimlik doğrulama ayarları
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = "Cookies"
            });

            // OpenID Connect kimlik doğrulama ayarları
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                TokenValidationParameters = tokenValidationParameters,
                AuthenticationType = "OpenIdConnect",
                ClientId = clientId,
                Authority = authority,
                RedirectUri = redirectUri,
                PostLogoutRedirectUri = postLogoutRedirectUri,
                ClientSecret = clientSecret,
                ResponseType = "code",
                ResponseMode = "form_post",
                Scope = "openid email",
                SignInAsAuthenticationType = "Cookies",
                SaveTokens = false,
                RedeemCode = true,
                MetadataAddress = "https://localhost:5001/.well-known/openid-configuration",               
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    RedirectToIdentityProvider = n =>
                    {
                        if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
                        {
                            var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token").Value;
                            n.ProtocolMessage.IdTokenHint = idTokenHint;
                        }
                        return Task.FromResult(0);
                    },
                    //AuthorizationCodeReceived = async n =>
                    //{
                    //    // PKCE için code_verifier oluştur
                    //    var codeVerifier = PKCEGenerator.GenerateCodeVerifier();
                    //    var codeChallenge = PKCEGenerator.GenerateCodeChallenge(codeVerifier);

                    //    // Daha sonra code_challenge ile token isteği yapabilirsiniz
                    //    var tokenEndpoint = "https://localhost:5001/connect/token";
                    //    var parameters = new Dictionary<string, string>
                    //        {
                    //            { "client_id", clientId },
                    //            { "client_secret", clientSecret },
                    //            { "code", n.Code },
                    //            { "redirect_uri", redirectUri },
                    //            { "code_verifier", codeVerifier },
                    //            { "code_challenge", codeChallenge },
                    //            { "grant_type", "authorization_code" }
                    //        };

                    //    var content = new FormUrlEncodedContent(parameters);

                    //    using (var client = new HttpClient())
                    //    {
                    //        var response = await client.PostAsync(tokenEndpoint, content);
                    //        if (response.IsSuccessStatusCode)
                    //        {
                    //            var responseContent = await response.Content.ReadAsStringAsync();
                    //            var tokenResponse = JsonConvert.DeserializeObject<TokenResponse>(responseContent);

                    //            var userInfoEndpoint = "https://localhost:5001/connect/userinfo";

                    //            var userInfoRequest = new UserInfoRequest
                    //            {
                    //                Address = userInfoEndpoint,
                    //                Token = tokenResponse.AccessToken
                    //            };

                    //            var userInfoResponse = await client.GetUserInfoAsync(userInfoRequest);

                    //            var identity = new ClaimsIdentity(n.AuthenticationTicket.Identity.AuthenticationType);
                    //            identity.AddClaims(userInfoResponse.Claims);

                    //            n.AuthenticationTicket = new AuthenticationTicket(identity, n.AuthenticationTicket.Properties);
                    //        }
                    //        else
                    //        {
                    //            var errorResponse = await response.Content.ReadAsStringAsync();
                    //            throw new Exception($"Token request failed: {errorResponse}");
                    //        }
                    //    }
                    //},
                    AuthenticationFailed = n =>
                    {
                        // Hata mesajını loglama
                        System.Diagnostics.Trace.TraceError("Authentication failed: " + n.Exception.ToString());

                        n.HandleResponse();
                        n.Response.Redirect("/Home/Error?message=" + n.Exception.Message);
                        return Task.FromResult(0);
                    },
                    SecurityTokenValidated = async n =>
                    {
                        // Access token'ı al
                        var accessToken = n.ProtocolMessage.AccessToken;
                        var userInfoEndpoint = "https://localhost:5001/connect/userinfo";
                        var userInfoRequest = new UserInfoRequest
                        {
                            Address = userInfoEndpoint,
                            Token = accessToken
                        };
                        var client = new HttpClient();
                        var userInfoResponse = await client.GetUserInfoAsync(userInfoRequest);

                        var identity = new ClaimsIdentity(n.AuthenticationTicket.Identity.AuthenticationType);
                        identity.AddClaims(userInfoResponse.Claims);

                        n.AuthenticationTicket = new AuthenticationTicket(identity, n.AuthenticationTicket.Properties);
                        // accessToken'ı kullanmak için yapılacak işlemler
                    }
                },
                Configuration = new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration
                {
                    JwksUri = "https://localhost:5001/.well-known/openid-configuration/jwks",
                    Issuer = "http://securify-adminconsole:60000",
                    AuthorizationEndpoint = "https://localhost:5001/connect/authorize",
                    TokenEndpoint = "https://localhost:5001/connect/token",
                    UserInfoEndpoint = "https://localhost:5001/connect/userinfo",
                    EndSessionEndpoint = "https://localhost:5001/connect/endsession",
                    CheckSessionIframe = "https://localhost:5001/connect/checksession"
                },
            });


            // Middleware ekle
            app.Use(async (context, next) =>
            {
                context.Set<TokenValidationParameters>("TokenValidationParameters", tokenValidationParameters);
                await next.Invoke();
            });
        }
    }
}
