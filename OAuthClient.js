/*
  OAuthClient for Joyent Smart Platform Sammy
  Created by: Matt Constantine
  Includes the NetFlix OAuth javascript client. See oauth.js for the license.
*/

system.use("oauth-client.oauth");
system.use("oauth-client.sha1");

OAuthClient = {
  
  initialize: function(options) {
    OAuthClient.options = options;
    
    GET(options.loginPath, function(){
      response = OAuthClient.sendRequest( options, {action: options.requestTokenURL } )
      if (response.code != 200) { return options.requestTokenFailed() }
      return( redirect(options.userAuthorizationURL + "?" + response.content) )
    })
  
    GET(options.callbackPath, function(){
      response = OAuthClient.sendRequest( options, {action: options.accessTokenURL, oauth_token: this.request.query.oauth_token} )
      if (response.code != 200) { return options.accessTokenFailed() }
      var person = OAuthClient.savePerson(response.content)
      this.session.person_id = person.id
      this.session.save()
      return redirect( options.returnPath )
    })
    
  },
  
  sendRequest: function(options, requestOptions) {
    var accessor = { consumerSecret: options.consumerSecret,
                     tokenSecret   : options.tokenSecret};
    var message =  { method: 'POST',
                     parameters: [["oauth_consumer_key", options.consumerKey],
                                  ["oauth_signature_method", options.signatureMethod]]
                   };
    message.action = requestOptions.action
    if( typeof(requestOptions.oauth_token) != 'undefined') {
      message.parameters.push(["oauth_token", requestOptions.oauth_token])  
    }
    OAuth.setTimestampAndNonce(message)
    OAuth.SignatureMethod.sign(message, accessor)
    return system.http.request(message.method, message.action, null, OAuth.formEncode(message.parameters))
  },
  
  //example body: oauth_token=asdfasdfasdf&oauth_token_secret=jkljkljkl&user_id=111111&screen_name=thismatt
  savePerson: function(body) {
    var options = OAuthClient.options
    params = body.split('&')
    var person = new options.model
    for(var i=0; i<params.length; i++) {  //my kingdom for a foreach
      param = params[i].split('=')
      person[param[0]] = param[1]
    }
    person.save()
    return person
  }
    
}

// Uses the system.digest.hmac if enabled. To enable, append 'HMAC' (without quotes) to the rsp.conf extensions line.
// Otherwise it uses the sha1.js which may require a higher oplimit in rsp.conf.  If you get blank responses, try 
// raising th oplimit to 200000. -mc 2009-07-27
if( system.digest.hmac != null ) {
  OAuth.SignatureMethod.registerMethodClass(["HMAC-SHA1", "HMAC-SHA1-Accessor"],
      OAuth.SignatureMethod.makeSubclass(
          function getSignature(baseString) {
              b64pad = '=';
              var signature = system.digest.hmac.sha1.base64(baseString, this.key) + "=";
              return signature;
          }
  ));
}
