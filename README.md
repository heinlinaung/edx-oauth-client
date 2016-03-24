# edx_wp_oauth_client
SSO Client for [Wordpress OAuth plugin provider][wp_oauth_provider].
### Instalation guide
 - Install  WP plugin following instruction. In wp-admin OAuth Server tab add new client.
Redirect uri must be **http://<edx_url>/auth/complete/wp-oauth2/**

 - Install this client
   ```
   pip install -e git+https://github.com/xahgmah/edx-wp-oauth-client.git#egg=edx_wp_oauth_client
   ```

 - Enable THIRD_PARTY_AUTH in edX
 
    In the edx/app/edxapp/lms.env.json file, edit the file so that it includes the following line in the features section.       And add  this backend.
    ```
    ...
    "FEATURES" : {
        ...
        "ENABLE_COMBINED_LOGIN_REGISTRATION": true,
        "ENABLE_THIRD_PARTY_AUTH": true
    }
    ...
    "THIRD_PARTY_AUTH_BACKENDS":["edx_wp_oauth_client.backends.wp_oauth_client.WPOAuthBackend"]
    ```
   
 - Add in file **lms/envs/common.py**. It's preffered to place it somewhere at the top of the list
    ```
    INSTALLED_APPS = (
        ...
        'sso_edx_ml',
        ...
    )
    ```
    
 - Add provider config in edX admin panel /admin/third_party_auth/oauth2providerconfig/
   - Enabled - **true**
   - backend-name - **wp-oauth2**
   - Skip registration form - **true**
   - Skip email verification - **true**
   - Client ID from WP Admin OAuth Tab
   - Client Secret from WP Admin OAuth Tab
    
 - If you're want seamless authorization add middleware classes for SeamlessAuthorization (crossdomain cookie support needed)
   ```
   MIDDLEWARE_CLASSES += ("edx_wp_oauth_client.middleware.SeamlessAuthorization",)
   ```
   
   And add this code in **functions.php** for your wordpress theme
   ```
   $auth_cookie_name = "authenticated";
   
   add_action("wp_login", "set_auth_cookie");
   function set_auth_cookie()
   {
       global $auth_cookie_name, $user;
       $user_id =$user->ID;
       $auth_code = 1;
       if($auth_code) {
           setcookie($auth_cookie_name, $auth_code, $domain="*.<YOUR_DOMAIN>");
           setcookie($auth_cookie_name."_user", $user->nickname, $domain="*.<YOUR_DOMAIN>");
       }
   
   }
   add_action('wp_logout', 'remove_custom_cookie_admin');
   function remove_custom_cookie_admin() {
       global $auth_cookie_name;
       setcookie($auth_cookie_name, "", $domain="*.<YOUR_DOMAIN>");
       setcookie($auth_cookie_name."_user", "", $domain="*.<YOUR_DOMAIN>");
   }
   ```

 
**Note.** If you work on local devstack. Inside your edx’s vagrant in /etc/hosts add a row with your machines’s IP  and wordpress’s >vhost. For example:
```192.168.0.197 wp.local```

[wp_oauth_provider]: <https://ru.wordpress.org/plugins/oauth2-provider/>
