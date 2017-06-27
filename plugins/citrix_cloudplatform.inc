#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# citrix_cloudplatform.inc
#
# $Revision: 1.2 $
#
# @include audit.inc
# @include misc_func.inc
###

##
# The KB root under which all API Call results will be stored
##
global_var CITRIX_CP_API_KB_BASE;
CITRIX_CP_API_KB_BASE = "Citrix/Cloudplatform/APICalls/";

##
# Specific error codes
##
global_var CITRIX_CP_ERROR_NO_HTTPS;
CITRIX_CP_ERROR_NO_HTTPS  = -4;
global_var CITRIX_CP_ERROR_COM;
CITRIX_CP_ERROR_COM       = -3;
global_var CITRIX_CP_ERROR_NO_CREDS;
CITRIX_CP_ERROR_NO_CREDS  = -2;
global_var CITRIX_CP_ERROR_AUTH_FAIL;
CITRIX_CP_ERROR_AUTH_FAIL = -1;

##
# Makes an API request to a Citrix Cloudplatform instance using provided session keys.
# If an identical request has already been made, returns the result from the previous
# request as stored in the KB
#
# @param string/int port       the port to connect to the API on, required
# @param string     command    the API command to call, required
# @param string     jsessionid the JSESSIONID of an established authenticated session, required
# @param string     sessionkey the API session key of an established authenticated session, required
# @param array      params     an array of additional parameters to send with the API command,
#                              they will be appended like so: key1=value1&key2=value2.  Values will
#                              be url encoded.  These values are part of the key/value pairs will be
#                              encoded into the KB item set for the call being executed as to not 
#                              overwrite KB items for the same command with different parameters
#
# @return :  CITRIX_CP_ERROR_COM if there was an error communicating with the API
#            NULL                if missing a required argument or an invalid argument was supplied
#            JSON response       otherwise
#
##
function cloudplatform_api_kb_item(port,command,jsessionid,sessionkey,params)
{
  local_var plist,item,res,kbitem,param,fname,errors,error;
  fname = "citrix_cloud_platform.inc::cloudplatform_api_kb_item";

  # Arg check
  errors = make_list();
  if(isnull(command))                          errors = make_list(errors,fname+" : Missing 'command' argument");
  else if(typeof(command) !~ "string|data")    errors = make_list(errors,fname+" : Argument 'command' must be a string type");
  if(isnull(jsessionid))                       errors = make_list(errors,fname+" : Missing 'jsessionid' argument");
  else if(typeof(jsessionid) !~ "string|data") errors = make_list(errors,fname+" : Argument 'jsessionid' must be a string type");
  if(isnull(sessionkey))                       errors = make_list(errors,fname+" : Missing 'sessionkey' argument");
  else if(typeof(sessionkey) !~ "string|data") errors = make_list(errors,fname+" : Argument 'sessionkey' must be a string type");
  if(isnull(port))                             errors = make_list(errors,fname+" : Missing 'port' argument");
  else if(typeof(port) !~ "string|data|int")   errors = make_list(errors,fname+" : Argument 'port' must be a string or int type");
  # Print errors, return
  if(max_index(errors) > 0)
  {
    foreach error (errors) err_print(error);
    return NULL;
  }

  # Default params to empty array
  if(isnull(params)) params = make_array();

  ##########################################
  # URI encode the parameter list for a GET request
  plist = NULL;
  if(!empty_or_null(res))
  {
    plist = make_list();
    foreach param (keys(params))
      plist = make_list(plist,param + "=" + urlencode(str:params[param]));
    plist =  join(plist,sep:"&");
  }
  ##########################################

  res  = NULL;
  item = "command="+command;
  if(!isnull(plist)) item += "&"+plist;

  ########################
  # Make KB safe item name
  kbitem = item;
  kbitem = base64(str:kbitem);
  kbitem = str_replace(string:kbitem, find:'=', replace:'$');
  kbitem = str_replace(string:kbitem, find:'/', replace:'^');
  kbitem = CITRIX_CP_API_KB_BASE+kbitem;
  ########################

  # Check to see if we've made this call before
  res = get_kb_item(kbitem);
  if(!isnull(res))
    return res;

  # Append authentication params
  item += "&sessionkey="+sessionkey+"&response=json";

  res = http_send_recv3(
    port         : port,
    method       : 'GET',
    # JSESSIONID is a cookie not a URI param
    add_headers  : make_array("COOKIE","JSESSIONID="+jsessionid),
    item         : "/client/api?"+item
  );

  # Something is not right
  if(empty_or_null(res))
    return CITRIX_CP_ERROR_COM;

  set_kb_item(name:kbitem,value:res[2]);
  return res[2];
}

##
# Tries to login into the Citrix CloudPlatform REST API.
#
# @param string/int port     the port on which CloudPlatform runs, required
# @param string     username the username to try and log in as
# @param string     password the password to use to log in with
#
# If user / password are not provided as arguments, they will be set to
# the kb items http/login and http/password.
#
# @return :  CITRIX_CP_ERROR_AUTH_FAIL if auth failed
#            CITRIX_CP_ERROR_NO_CREDS  if no creds where provided
#            CITRIX_CP_ERROR_COM       if there was an error
#            an array  if login succeed:
#            {
#               "version",    <Cloudplatform version>,
#               "JSESSIONID", <JSESSIONID of login session>,
#               "sessionkey", <API Session key of login>
#            }
#
#  Note: sessionkey and JESSIONID can be used to make further
#        API calls for configuration checking
##
function cloudplatform_login(port,username,password,send_plaintext)
{
  local_var res,post,version,key,jsessionid,fname,error,errors,encaps;
  fname = "citrix_cloud_platform.inc::cloudplatform_login";

  # Check args
  errors = make_list();
  if(isnull(port))                             errors = make_list(errors,fname+" : Missing 'port' argument");
  else if(typeof(port) !~ "string|data|int")   errors = make_list(errors,fname+" : Argument 'port' must be a string or int type");
  if(!isnull(username) && typeof(username) !~ "string|data") errors = make_list(errors,fname+" : Argument 'username' must be a string or int type");
  if(!isnull(password) && typeof(password) !~ "string|data") errors = make_list(errors,fname+" : Argument 'password' must be a string or int type");
  # If one is provided the other is required
  if(!isnull(password) && isnull(username)) errors = make_list(errors,fname+" : Argument 'password' is provided but not argument 'username'");
  if(!isnull(username) && isnull(password)) errors = make_list(errors,fname+" : Argument 'username' is provided but not argument 'password'");
  if(max_index(errors) > 0)
  {
    foreach error (errors) err_print(error);
    return NULL;
  }

  # Set defaults
  if(isnull(username) && isnull(password))
  {
    username = get_kb_item("http/login");
    password = get_kb_item("http/password");
  }
  if(isnull(username) || isnull(password))
    return CITRIX_CP_ERROR_NO_CREDS;

  if(isnull(send_plaintext)) send_plaintext = FALSE;

  encaps = get_port_transport(port);
  if ((!encaps || encaps <= ENCAPS_IP) && !send_plaintext)
    return CITRIX_CP_ERROR_NO_HTTPS;

  post = 'command=login'  +
         '&domain=%2F'    +
         '&response=json' +
         '&password=' + password +
         '&username=' + username;

  res = http_send_recv3(
    port         : port,
    method       : 'POST',
    item         : "/client/api",
    data         : post,
    content_type : "application/x-www-form-urlencoded",
    exit_on_fail : TRUE
  );

  # Everything was ok, but authentication failed
  if(res[0] =~ '^HTTP.*(531|401 Unautherized)')
    return CITRIX_CP_ERROR_AUTH_FAIL;
  # All other errors
  if(res[0] !~ "200 OK")
    return CITRIX_CP_ERROR_COM;

  jsessionid = eregmatch(pattern:'JSESSIONID=([0-9A-Za-z]+);',string:res[1]);
  if(empty_or_null(jsessionid)) 
    return CITRIX_CP_ERROR_COM;

  key = eregmatch(pattern:'"sessionkey"\\s*:\\s*"(.+)",',string:res[2]);
  if(empty_or_null(key))
    return CITRIX_CP_ERROR_COM;
  key = urlencode(str:key[1]);

  res = http_send_recv3(
    port         : port,
    method       : 'GET',
    item         : "/client/api?command=listCapabilities&response=json&sessionkey="+key,
    exit_on_fail : TRUE
  );

  if(res[0] !~ "200 OK")
    return CITRIX_CP_ERROR_COM;
  version = eregmatch(pattern:'"cloudstackversion"\\s*:\\s*"([0-9.]+)"',string:res[2]);
  if(empty_or_null(version))
    return CITRIX_CP_ERROR_COM;

  return make_array(
    "version",version[1],
    "sessionkey",key,
    "JSESSIONID",jsessionid
  );
}

##
# Checks API response to see if higher privileges / authentication is
# required to successfully perform the call the generated the
# response
#
# @param string apibuf the response buffer from the last API call, required
#
# @return TRUE if apibuf indicates more auth is required for the API call
#         NULL if apibuf is a bad type or not provided
#         that generated it, FALSE otherwise
##
function cloudplatform_needs_authentication(apibuf)
{
  if(isnull(apibuf) && max_index(_FCT_ANON_ARGS) > 0) apibuf = _FCT_ANON_ARGS[0];
  else
  {
    err_print("citrix_cloud_platform.inc::cloudplatform_needs_authentication : Missing 'apibuf' argument");
    return NULL;
  }
  if(typeof(apibuf) !~ "string|data")
  {
    err_print("citrix_cloud_platform.inc::cloudplatform_needs_authentication : Argument 'apibuf' must be a string type");
    return NULL;
  }
  # Error code 401 always returned for unauthentication
  return apibuf =~ '"errorcode"\\s*:\\s*401[^0-9]';
}
