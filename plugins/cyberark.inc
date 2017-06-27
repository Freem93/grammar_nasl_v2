#TRUSTED 24523019fe5c9b4d4b9af84bbe368438c3fc668bfe49d4e90e2987bf63d7cfc70d5601f22d3c434546d528441fab62f7171d8cbc2341fef8eeee189e2a307695c000b521ff03d3d974c8a323b227a54928bf9effac6b5d170a6af72b447201f24360e76678f842eb493aa2afecf85c2b379bc6d5c3186189cb6a01b4b3d64030d7dacde1ebd8fae3a23413f7fcf44b7590584cc5abb175d7135d35e5b62c47802be3ab8743e27d8a7a3d85d79d5ca63416052705226577d443d1e7184770f6f3e71eab8ee8e8708de732c95c07471fd95b8f44043f97f1098de490618aa54e46d9a7e099eb01040b97694c143f2bc53ef566d5871fe8711fc5bae50b54e44f8b22369256e9b6fefc5bb59714440be74de6ea1bce6eaccff17f2faaff3cf3134a5f77cd08950c32f54d65c7260097aa9afc46a35d9645785a20a22e7de8c473be4aae1448b979afa69873367645b9f3466970d559a452e5799e33624883cd5e5a7ab01f49056a42d1f20bedf0e072e9c20808bed7273b552fad92fa0b0ef44412b6ffc7517b2bb610329bc661b0a16bc584e758dbeaf097b2206c2feb86468b36b25b0188d8d5009b81424fef237b555970c9a36e81013585200163c107305c52cc1a666440ff364965c4fdf930e689cf7f14c26127e56a6a364ddcb6c0110c24cc5181f7fd72f0eed8a5aa7eea68ce989d4e73375d28d2f06166612805ea7c5a
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: ?
#

global_var CARK_TRANSPORT, CARK_USERNAME, CARK_PASSWORD, CARK_TARGET, CARK_PORT, CARK_SSL, CARK_DEBUG, CARK_URL;
global_var CARK_LAST_ERROR; # contains the last error sent to cark_error
global_var ERROR_EXIT; # Create an audit trail message when calling cark_error()
global_var ERROR_LOG; # Log errors to the stack without an exit call in cark_error()

ERROR_EXIT = 1;
ERROR_LOG = 2;

##
# Initialize the cyberark communication information
#
# @param [debug:bool] enable debugging output
# @param [target:string] the target IP or DNS
# @param [port:int] the port cyberark is running on
# @param [ssl:bool] if the server is using ssl
# @param [ssl_verify:bool] verify ssl cert
# @param [username:string] username if the server has one
# @param [passwod:string] password if the server has one
# 
# @return list of possible address values for the target
##
function cark_init(debug, target, domain, port, ssl, ssl_verify, username, password, cark_url)
{
  local_var account_type, system_name, host_ip;

  if(get_kb_item("global_settings/enable_plugin_debugging") || debug)
    CARK_DEBUG = TRUE;

  if (empty_or_null(cark_url))
  {
    cark_url = "/AIMWebservice/v1.1/AIM.asmx";
  }

  CARK_USERNAME = username;
  CARK_PASSWORD = password;
  CARK_TARGET = target;
  CARK_PORT = port;
  CARK_TRANSPORT = ssl_transport(ssl:ssl, verify:ssl_verify);
  CARK_URL = cark_url;

  system_name = cark_get_system_name(); #0. name supplied in UI
  host_ip = get_host_ip();

  account_type = make_list();
  if (!isnull(system_name)) account_type = make_list(account_type, system_name);
  if (!isnull(domain)) account_type = make_list(account_type, domain);
  if (!isnull(host_ip) && system_name != host_ip) account_type = make_list(account_type, host_ip);

  spad_log(message:'Cyberark Settings ~' +
           '\nCARK_DEBUG : ' + CARK_DEBUG +
           '\nCARK_USERNAME : ' + CARK_USERNAME +
           '\nCARK_PASSWORD : ' + CARK_PASSWORD + 
           '\nCARK_TARGET : ' + CARK_TARGET +
           '\nCARK_PORT : ' + CARK_PORT +
           '\nCARK_TRANSPORT : ' + CARK_TRANSPORT +
           '\nCARK_URL : ' + CARK_URL +
           '\nsystem_name : ' + system_name +
           '\ndomain : ' + domain +
           '\nhost_ip : ' + host_ip
           );

  return account_type;
}

##
# obtain the system name as it is reported in the UI
##
function cark_get_system_name()
{
  local_var Host, myHostName;

  myHostName = get_kb_item("myHostName");
  if ( !isnull(myHostName) ) return myHostName;

  Host = get_host_report_name();

  if (!isnull(Host))
  {
    replace_kb_item(name:"myHostName", value:Host);
  }

  return Host;
}

##
# Return the last error 
#
# @return string last error
##
function cark_get_last_error()
{
  return CARK_LAST_ERROR;
}

##
# cyberark error logging
#
# @anonparam [int] exit code 0 or 1
# @anonparam [string] exit message 
# @param [report_error_title:string] report_error title
# @param [report_error_severity:string] report_error severity
# @param [severity:const] ERROR_EXIT | ERROR_LOG depending on what is required
# 
# @return NULL
##
function cark_error(report_error_title, report_error_severity, severity)
{
  # Log any bad error messages
  if (_FCT_ANON_ARGS[0] != 0 && _FCT_ANON_ARGS[0] != 1)
  {
    cark_error(1, "Bad error code in cark_error.", severity:severity);
    return NULL;
  }

  if (isnull(_FCT_ANON_ARGS[1]))
  {
    cark_error(1, "No message supplied for cark_error.", severity:severity);
    return NULL;
  }

  CARK_LAST_ERROR = _FCT_ANON_ARGS[1];
  spad_log(message:CARK_LAST_ERROR ,name:SCRIPT_NAME + "~Cyberark");

  if (report_error_title && report_error_severity)
    report_error(title:SCRIPT_NAME + ": " + report_error_title, message:_FCT_ANON_ARGS[1], severity:report_error_severity);

  if (severity == ERROR_EXIT) exit(_FCT_ANON_ARGS[0], _FCT_ANON_ARGS[1]);

  return NULL;
}

##
# Validate the HTTP status
#
# @param [status_line:string] the HTTP status line
#
# @return int status code or NULL if error or status_line does not
#             contain an HTTP status of 20x, 40x, or 50x
##
function cark_ValidateResp(status_line)
{
  local_var errorMsg;

  if (status_line =~ '^HTTP/1\\.[01] +200')
  {
    return 200;
  }
  else if (status_line =~ '^HTTP/1\\.[01] +40[0-9]')
  {
    cark_error(1, 
               chomp(status_line) + " returned", 
               severity:ERROR_LOG);

    return 400;
  }
  else if (status_line =~ '^HTTP/1\\.[01] +50[0-9]')
  {
    errorMsg = chomp(status_line) + " returned";

    cark_error(1,
               errorMsg,
               severity:ERROR_LOG);

    return 500;
  }
  else
  {
      cark_error(1,
                 chomp(status_line) + " returned",
                 severity:ERROR_LOG);
  }

  return NULL;
}

##
# Check for 'faultstring' XML element in return value to determine proper 
# error message
#
# @param [xml:string] result body
#
# @return NULL
##
function cark_check_500_return(xml)
{
  local_var match;

  match = eregmatch(pattern:"<faultstring>(.+)<\/faultstring>", string:xml, icase:FALSE);
  if (!isnull(match[1])) cark_error(0,"HTTP 500 : " + match[1], severity:ERROR_LOG);
  else cark_error(0,"HTTP 500 : " + xml, severity:ERROR_LOG);

  return NULL;
}

##
# Parse the response from cyberark
#
# @param [xml:string] request body
#
# @return array containing Username and Password or NULL if errors
##
function cark_parse_results(xml)
{
  local_var val_table, creds, xml_stack, i, obj;

  creds = make_array(); # setup credential storage unit

  # parse XML 
  # val_table = deserialize(options:SERIALIZE_XML, xml);
  val_table = xmlparse(xml);

  if (isnull(val_table))
  {
    cark_error(0, "Invalid XML response, failed to parse soap response.", severity:ERROR_LOG);
    return NULL;
  }

  # This list is used to validate the XML tree.
  xml_stack = make_list("soap:Envelope","soap:Body","GetPasswordResponse"); 
  i = 0; # index counter into xml_stack
  while (TRUE)
  {
    # This loop will recurse over the data structure returned from 
    # deserialize validating the XML stack, if it any point the stack
    # does not match it will log the error and return
    # we should only ever have to worry about 1 tree structure because
    # cyberark only will ever return 1 item at a time even when multiple
    # objects on the server match the parameters

    if (val_table["name"] == xml_stack[i])
    {
      val_table = val_table["children"][0]; # change the table pointer to the child unit
      if (val_table)
      {
        i++;
        continue;
      }
      else
      {
        cark_error(0, "Invalid XML response : missing " + xml_stack[i], severity:ERROR_LOG);
        return NULL;
      }
    }
    else
    {
      # Once the chain is validated one final validation is done here before parsing out 
      # the creds from the containing tags
      if (val_table["name"] == "GetPasswordResult")
      {
        foreach obj (val_table["children"])
        {
          if (obj["name"] == "Content") creds["Password"] = obj["value"];
          else if (obj["name"] == "UserName") creds["Username"] = obj["value"];
        }
        break;
      }
      else
      {
        cark_error(0, "Invalid XML response : invalid tag = " + val_table["name"], severity:ERROR_LOG);
        return NULL;
      }
    }
  }

  # If no credentials where supplied from the server we log the error and return null
  if (isnull(creds["Username"]) || isnull(creds["Password"]))
  {
    cark_error(0, "Invalid XML response : Unable to obtain credentials.", severity:ERROR_LOG);
    return NULL;
  }

  return creds;
}

##
# assemble the request based on the parameters supplied
#
# @param [uri:string] optional parameter to change the uri in the request
# @param [parameters:array] an array of parameters supplied to cark_get_password
#
# @return string xml request
##
function cark_build_request(uri, parameters)
{
  local_var xml, kv;

  # This is not required at this time so we use tempuri.org as supplied from their docs
  if (isnull(uri)) uri = "https://tempuri.org/";

  xml = '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body><GetPassword xmlns="https://tempuri.org/"><passwordWSRequest>';

  if (parameters["AppID"]) xml += '<AppID>'+parameters["AppID"]+'</AppID>';
  if (parameters["Safe"]) xml += '<Safe>'+parameters["Safe"]+'</Safe>';
  if (parameters["Folder"]) xml += '<Folder>'+parameters["Folder"]+'</Folder>';
  if (parameters["Object"]) xml += '<Object>'+parameters["Object"]+'</Object>';
  if (parameters["Username"]) xml += '<UserName>'+parameters["Username"]+'</UserName>';
  if (parameters["Address"]) xml += '<Address>'+parameters["Address"]+'</Address>';
  if (parameters["Database"]) xml += '<Database>'+parameters["Database"]+'</Database>';
  if (parameters["PolicyID"]) xml += '<PolicyID>'+parameters["PolicyID"]+'</PolicyID>';

  # This is a log on the cyberark server explaining the purpose for the request. 
  # This is defaulted to Nessus but can be controlled.
  if (parameters["Reason"]) xml += '<Reason>'+parameters["Reason"]+'</Reason>';
  else xml += '<Reason>NESSUS</Reason>';

  # Default to 5 second but can be controlled through parameters
  if (parameters["ConnectionTimeout"]) xml += '<ConnectionTimeout>'+parameters["ConnectionTimeout"]+'</ConnectionTimeout>';
  else xml += '<ConnectionTimeout>5</ConnectionTimeout>';

  # This could potentially be set to Exact or Regex but for our purposes we will normally
  # just use Exact and it will default to this value. This tag is required.
  if (parameters["Query"]) xml += '<Query>'+parameters["Query"]+'</Query>';
  xml += '<QueryFormat>Exact</QueryFormat>';

  if (parameters["Attributes"])
  {
    xml += '<Attributes>';
    foreach kv (parameters["Attributes"])
    {
      xml += '<KeyAndValue><key>'+kv["key"]+'</key><value>'+kv["value"]+'</value></KeyAndValue>';
    }
    xml += '</Attributes>';

  }

  xml += '</passwordWSRequest></GetPassword></soap:Body></soap:Envelope>';

  return xml;
}

##
# Main call to get password information from cyberark
#
# @param [parameters:list] cyberark query parameters
# @remark list of available parameters
#   AppID:string
#   Safe:string
#   Folder:string
#   Object:string
#   Username:string
#   Address:string
#   Database:string
#   PolicyID:string
#   Reason:string
#   ConnectionTimeout:int
#   Query:string
#   Attributes:list
#   key:string
#   value:string
#   
# @return array containing Username and Password or NULL if errors
##
function cark_get_password(parameters)
{
  local_var res, data, http_status, ret, http_headers;

  data = cark_build_request(parameters:parameters);

  # username and password is optional for this product. It can be setup through IIS but their main form of security is IP whitelisting
  # this allows for the option to use username and password basic auth
  if (CARK_USERNAME && CARK_PASSWORD)
    http_headers = make_array("Content-Type","text/xml; charset=utf-8", "SOAPAction","https://tempuri.org/GetPassword",'Authorization','Basic '+base64(str:CARK_USERNAME +':'+ CARK_PASSWORD));
  else
    http_headers = make_array("Content-Type","text/xml; charset=utf-8", "SOAPAction","https://tempuri.org/GetPassword");

  if (CARK_DEBUG)
  {
    cark_error(0, 'HTTP_Request Body ~ ' + data + '\n');
  }

  res =  http_send_recv3(
    target       : CARK_TARGET,
    method       : "POST",
    item         : CARK_URL,
    port         : CARK_PORT,
    data         : data,
    add_headers  : http_headers,
    transport    : CARK_TRANSPORT, 
    exit_on_fail : FALSE
  );
  http_disable_keep_alive();

  if (isnull(res))
  {
    cark_error(1,
               "Cyberark did not respond to request.",
               report_error_title:"Cyberark No Response",
               report_error_severity:1,
               severity:ERROR_LOG);
    return NULL;
  }
  else if (CARK_DEBUG)
  {
    cark_error(0, "HTTP RESPONSE STATUS ~ " + res[0] );
    cark_error(0, "HTTP RESPONSE HEADERS ~ " + res[1] );
    cark_error(0, "HTTP RESPONSE BODY ~ " + res[2] );
  }

  http_status = cark_ValidateResp(status_line:res[0]);
  if (http_status == 200) ret = cark_parse_results(xml:res[2]);
  else if (http_status == 500) ret = cark_check_500_return(xml:res[2]);
  else return NULL;

  return ret;
}

##
# Demo function shows how the api works
##
function cyberark_demo()
{
  local_var target, port, ssl, ssl_verify, username, password, res, parameters;

  set_kb_item(name:"global_settings/enable_plugin_debugging", value:TRUE);

  target = "<target>";
  port = 0000;
  ssl = FALSE;
  ssl_verify = FALSE;
  username = NULL;
  password = NULL;
  cyberark_url = "/AIMWebservice/v1.1/AIM.asmx";  

  cark_init(debug:TRUE, target:target, port:port, ssl:ssl, ssl_verify:ssl_verify, username:username, password:password, cark_url:cyberark_url);
  parameters = make_array(
        "Username","<username>",
        "Safe","<safe>",
        "AppID","<appid>",
        "Folder","Root",
        "Address","<address>",
#        "Object", "<object>",
        "Reason","NESSUS"
        );

  res = cark_get_password(parameters:parameters);

  if (isnull(res))
  {
    exit(0, CARK_LAST_ERROR);
  }
  else
  {
    display(res);
    # set creds using res.Username and res.Password values
  }
}
