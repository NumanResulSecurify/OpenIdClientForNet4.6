# OpenIdClientForNet

Web.config dosyasındaki aşağıdaki satırlar Identity Server Uygulamasından Configüre edilmiş clientın bilgilerine göre güncellenmelidir
```xml
<add key="ClientId" value="oidcfornetmvc" />
<add key="ClientSecret" value="93ec28b7-cf7e-4f87-89e5-634d4cb14a15" />
<add key="Authority" value="https://localhost:5001" /> // identity server uygulamasının url'i
<add key="RedirectUri" value="https://localhost:44313" /> // identity serverdan login olunduktan sonra yönlenecek client uygulamasının url'i
<add key="PostLogoutRedirectUri" value="https://localhost:44313/Home/Index" /> // Identity serverdan Logout olunduktan sonra clienta dönülecek url
( identity server uygulamasındada bu url ilgili alana girilmeli)
```

Client uygulamasında OpenId ile ilgili genel ayarlar Startup.Auth.cs içerisinde bulunur. Kod sırasına göre burada bazı satırların ne için eklendiği aşağıda açıklanmıştır.

var tokenValidationParameters = new TokenValidationParameters bu tanımlama local ortamlarda çalışırken Signature validation hatası alınmaması için kullanıyor ve aşağıdaki Middleware içinde parametre olarak geçiliyor.

```csharp
 app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
 {
     TokenValidationParameters = tokenValidationParameters,     

}
```

Yine yukarıdaki OpenId miidlewareı içinde Server Tarafında yapılan confige göre Client configleri tanımlanıyor. Bazı congiglerin açıklamaları aşağıdaki gibidir;
```csharp
ResponseType = "code", // server tarafında AuthCodeFlow enabled olduğu için bu değişken "code" olarak kullanılmalıdır.
```
```csharp
 ResponseMode = "form_post", // serverden gelen cevabın headerdan değil body den iletilmesi için bu değer geçilir
```
```csharp
SignInAsAuthenticationType = "Cookies", // client uygulamasının cookiesi ve serverın oluşturduğu cookinin aynı olması ve işleyişin 
//düzgün çalışması için bu değerin içeriği ve aşağıda yazılmış olan cilent middlewarındaki içerik aynı olmalıdır.
```

```csharp
app.UseCookieAuthentication(new CookieAuthenticationOptions
{
    AuthenticationType = "Cookies"
});
```

```csharp
Notifications = new OpenIdConnectAuthenticationNotifications
{

}
// bu parametre server tarafında tetikjlenen ve sonuçlanan süreçlerin handle edildiği parametredir örneğin herhangi
// bir redirect işlemi oluştuğunda mesela logout yapıldığında yapılacak işlemler
// aşağıdaki parametre ile handle edilir 
```

```csharp
RedirectToIdentityProvider = n =>
{
    if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.Logout)
    {
        var idTokenClaim = n.OwinContext.Authentication.User.FindFirst("id_token");
        if (idTokenClaim != null)
        {
            n.ProtocolMessage.IdTokenHint = idTokenClaim.Value;
        }
        n.ProtocolMessage.PostLogoutRedirectUri = postLogoutRedirectUri;
    }
    return Task.FromResult(0);
},
```

Mesela Authentication fail olduğunda aşağıdaki kısım çalışr
```csharp
AuthenticationFailed = n =>
{

}
```

Aşağıdaki parametre ise servera gönderilen token valide edildiğinde tetiklerin projece buranın içinde userın claimlerini alabilmek için access tokenın serverin userinfo endpointine gönderiyoruz ve claimler ile birlikte idToken ve AccesTokenı contexte uygun yerlere  yerleştiriryoruz

```csharp
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
    n.AuthenticationTicket.Properties.Dictionary["id_token"] = n.ProtocolMessage.IdToken;
    n.AuthenticationTicket.Properties.Dictionary["access_token"] = n.ProtocolMessage.AccessToken;
}
```

Configuration parametresine OIDC Server projemizden ayağa kalkan endpointlerini manuel olarak tanımlayabiliyioruz.








