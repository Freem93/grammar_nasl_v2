#TRUSTED 029e7c404f25df3b59de2c6cf57e63355491dbbcb7cfdd665a5b37869e8a36bc5c79a1286b6925b63600de478f42f0a263c36920a9627f17844aab369ba0737099707903b0ce7b96849232c085f7d31ed809feabc3ab97ace770cfdddd03a4e62872dc171d76aa9e47697562737df2380b915b5ad0f5a70fddb7e1fd2dfac091e7940320660da34e8947690b4c98626e094d91e12ce9576f40defbbe645536c045877d019039d2763f4cb5f4b5e741fa5fd4b4a6c2dd53e54d831c2bd5fe758ad56357960b1ef0511241af6e99a12759acad93470a1c38cc72fea7b11960bee6db839778fe1b8649e40898796d3864b60eb325466929af0449ce221627c7e6f5bc2eebb7971a3a7cf3ffc30ea93b8f89f3b214cb8b13aa8e27646441c74b98775d130b379674020683c06eb5649c7a73e86d76395f5681f93d12f669e6b9e3373032abeb6bbd23e0f9fd5a95b775a5bdc6189821482f831f5558c4123dbfa2c970dadce3a0d6003032c4c0ce1423d346b4ed9a0155ba7aee2afe42092630e090d25bd7704eb2debfdace2d013b5619665709475156078a20304e6ebceb6ac651131564a77d261bae638697c41b11c0b61afcf8a46803e23f30675605859c40013725cf75ebdc817bbcd2a7e5ae1d73830dada60f4b72de548efb9d25a0777bd68044275f134ea4bae8be946a1d747da7fce52b403511ac24f8d8aa87ad0e1220

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

global_var THYCOTIC_LAST_ERROR, ERROR_EXIT, ERROR_LOG;
global_var THYCOTIC_USERNAME, THYCOTIC_PASSWORD,THYCOTIC_ORGANIZATION,
  THYCOTIC_DOMAIN,THYCOTIC_TARGET,THYCOTIC_PORT,THYCOTIC_TRANSPORT, THYCOTIC_DEBUG,
  THYCOTIC_TOKEN, THYCOTIC_DIR, THYCOTIC_PRIVATE_KEY;

ERROR_EXIT = 1;
ERROR_LOG = 0;

##############################
## Debug and Error Handling ##
##############################

##
# Log error messages for thycotic to the debugging API
#
# @param [msg:string] the message to log
#
# @return NULL
##
function thycotic_log_debug(msg)
{
  spad_log(message:msg,name:"Thycotic");
}

##
# Log errors produced from thycotic api and plugins
#
# @anonparam [int] exit code 0 or 1
# @anonparam [string] exit message
# @param [report_error_title:string] report_error title
# @param [report_error_severity:string] report_error severity
# @param [severity:const] ERROR_EXIT | ERROR_LOG depending on what is required
#
# @return NULL
##
function thycotic_error(report_error_title, report_error_severity, severity)
{
  # Log any bad error messages
  if (_FCT_ANON_ARGS[0] != 0 && _FCT_ANON_ARGS[0] != 1)
  {
    thycotic_error(1, "Bad error code in thycotic_error.", severity:severity);
    return NULL;
  }

  if (isnull(_FCT_ANON_ARGS[1]))
  {
    thycotic_error(1, "No message supplied for thycotic_error.", severity:severity);
    return NULL;
  }

  THYCOTIC_LAST_ERROR = _FCT_ANON_ARGS[1];
  thycotic_log_debug(msg:THYCOTIC_LAST_ERROR);

  if (report_error_title && report_error_severity)
    report_error(title:SCRIPT_NAME + ": " + report_error_title, message:_FCT_ANON_ARGS[1], severity:report_error_severity);

  if (severity == ERROR_EXIT) exit(_FCT_ANON_ARGS[0], _FCT_ANON_ARGS[1]);

  return NULL;
}

##
# Get the last error from thycotic
##
function thycotic_get_last_error()
{
  return THYCOTIC_LAST_ERROR;
}

######################
## Public Functions ##
######################

function thycotic_privatekey_enabled()
{
  return THYCOTIC_PRIVATE_KEY;
}

##
# Prepare settings for thycotic
# Secret Server URL
##
function thycotic_init(username, password, organization, domain, secret_server_url, ssl_verify, private_key, debug)
{
  local_var parsed_url;

  if(get_kb_item("global_settings/enable_plugin_debugging") || debug) THYCOTIC_DEBUG = TRUE;

  # Parse the secret server url into target and the SecretServer root install location
  # http://192.168.1.11/SecretServer/
  parsed_url = thycotic_parse_url(url:secret_server_url);
  if (isnull(parsed_url))
  {
    thycotic_error(0, "Failed to parse the Thycotic Secret Server URL.", severity:ERROR_LOG);
    return NULL;
  }

  if (THYCOTIC_DEBUG)
  {
    if (isnull(username))
    {
      thycotic_error(0, "Thycotic is missing username parameter.", severity:ERROR_LOG);
      return NULL;
    }
    else if (isnull(password))
    {
      thycotic_error(0, "Thycotic is missing password parameter.", severity:ERROR_LOG);
      return NULL;
    }
    else if (isnull(secret_server_url))
    {
      thycotic_error(0, "Thycotic is missing secret_server_url parameter.", severity:ERROR_LOG);
      return NULL;
    }
  }
  else if (isnull(username) || isnull(password) || isnull(secret_server_url))
  {
    thycotic_error(0, "Thycotic is missing required parameter.", severity:ERROR_LOG);
    return NULL;
  }

  THYCOTIC_USERNAME = username;
  THYCOTIC_PASSWORD = password;
  THYCOTIC_ORGANIZATION = organization;
  THYCOTIC_DOMAIN = domain;
  THYCOTIC_TARGET = parsed_url["target"];
  THYCOTIC_DIR = parsed_url["directory"];
  THYCOTIC_PORT = parsed_url["port"];
  THYCOTIC_TRANSPORT = ssl_transport(ssl:parsed_url["ssl"], verify:ssl_verify);
  THYCOTIC_TOKEN = NULL;
  THYCOTIC_PRIVATE_KEY = private_key;

  return 1;
}

##
# Authenticate to the Thycotic server to get a
# Token for future queries
#
#
# @return token:string, null on failure
##
function thycotic_authenticate()
{
  local_var req, res, http_status, token, error_string, val_table, xml_stack, i, obj;

  req = THYCOTIC_DIR + "webservices/sswebservice.asmx/Authenticate?";
  req += "username="+THYCOTIC_USERNAME;
  req += "&password="+THYCOTIC_PASSWORD;
  req += "&organization="+THYCOTIC_ORGANIZATION;
  req += "&domain="+THYCOTIC_DOMAIN;

  res =  http_send_recv3(
    target       : THYCOTIC_TARGET,
    method       : "GET",
    item         : req,
    port         : THYCOTIC_PORT,
    transport    : THYCOTIC_TRANSPORT,
    exit_on_fail : FALSE
  );

  if (isnull(res))
  {
    thycotic_error(1,"Thycotic did not respond to request (Authenticate).",severity:ERROR_LOG);
    return NULL;
  }
  else if (THYCOTIC_DEBUG)
  {
    thycotic_log_debug(msg:"HTTP AUTHENTICATE STATUS ~ " + res[0] );
    thycotic_log_debug(msg:"HTTP AUTHENTICATE HEADERS ~ " + res[1] );
    thycotic_log_debug(msg:"HTTP AUTHENTICATE BODY ~ " + res[2] );
  }

  http_status = thycotic_ValidateResp(status_line:res[0]);
  if (http_status == 200)
  {
    val_table = xmlparse(res[2]);

    if (isnull(val_table))
    {
      thycotic_error(0, "Invalid XML response, failed to parse soap response.", severity:ERROR_LOG);
      return NULL;
    }

    xml_stack = make_list("soap:Envelope","soap:Body","AuthenticateResponse");
    i = 0; # index counter into xml_stack
    while (TRUE)
    {
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
          thycotic_error(0, "Invalid XML response : missing " + xml_stack[i], severity:ERROR_LOG);
          return NULL;
        }
      }
      else
      {
        # Once the chain is validated one final validation is done here before parsing out
        # the creds from the containing tags
        if (val_table["name"] == "AuthenticateResult")
        {
          foreach obj (val_table["children"])
          {
            if (obj["name"] == "Token") token = obj["value"];
            else if (obj["name"] == "Errors")
            {
              foreach obj (val_table["children"])
              {
                if (obj["name"] == "string")
                {
                  error_string = obj["value"];
                  thycotic_error(0, "Authenticate Error String : " + error_string);
                }
              }
            }
          }
          break;
        }
        else
        {
          thycotic_error(0, "Invalid XML response : invalid tag = " + val_table["name"], severity:ERROR_LOG);
          return NULL;
        }
      }
    }

    THYCOTIC_TOKEN = token;
    return TRUE;
  }
  else
  {
    thycotic_error(0, "Authentication Failed : " + res[0], severity:ERROR_LOG);
    return NULL;
  }
}

##
#
##
function thycotic_SearchSecretsByExposedValues(searchTerm, showDeleted, showRestricted, showPartialMatches)
{
  local_var req, http_headers, res, http_status, val_table, xml_stack, i, j, val_table_cache, items, creds, obj, SecretIds;

  req = '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <SearchSecretsByExposedValues xmlns="urn:thesecretserver.com">
      <token>'+THYCOTIC_TOKEN+'</token>
      <searchTerm>'+searchTerm+'</searchTerm>
      <showDeleted>'+showDeleted+'</showDeleted>
      <showRestricted>'+showRestricted+'</showRestricted>
      <showPartialMatches>'+showPartialMatches+'</showPartialMatches>
    </SearchSecretsByExposedValues>
  </soap:Body>
</soap:Envelope>';

  http_headers = make_array("Content-Type","text/xml; charset=utf-8", "SOAPAction","urn:thesecretserver.com/SearchSecretsByExposedValues");
  res =  http_send_recv3(
    target       : THYCOTIC_TARGET,
    method       : "POST",
    item         : THYCOTIC_DIR+"webservices/sswebservice.asmx",
    data         : req,
    add_headers  : http_headers,
    port         : THYCOTIC_PORT,
    transport    : THYCOTIC_TRANSPORT,
    exit_on_fail : FALSE
  );

  if (isnull(res))
  {
    thycotic_error(1,"Thycotic did not respond to request (SearchSecretsByExposedValues).",severity:ERROR_LOG);
    return NULL;
  }
  else if (THYCOTIC_DEBUG)
  {
    thycotic_log_debug(msg:"HTTP GetSecret STATUS ~ " + res[0] );
    thycotic_log_debug(msg:"HTTP GetSecret HEADERS ~ " + res[1] );
    thycotic_log_debug(msg:"HTTP GetSecret BODY ~ " + res[2] );
  }

  http_status = thycotic_ValidateResp(status_line:res[0]);
  if (http_status != 200)
  {
    thycotic_error(1,"Thycotic responded with " + res[0],severity:ERROR_LOG);
    return NULL;
  }

  val_table = xmlparse(res[2]);
  xml_stack = make_list("soap:Envelope","soap:Body","SearchSecretsByExposedValuesResponse", "SearchSecretsByExposedValuesResult", "SecretSummaries");
  i = 0; # index counter into xml_stack
  j = 0; # used to increase the counter in the list values
  while (TRUE)
  {
    if (val_table["name"] == xml_stack[i])
    {
      if (isnull(xml_stack[i+1])) break; # break out of the loop once we reach the last index value;

      val_table_cache = val_table; # used to cache the last position for indexing
      val_table = val_table["children"][j]; # change the table pointer to the child unit
      if (val_table)
      {
        j = 0; # if the index has matched then you need to reset the index values
        i++;
        continue; # move to the next index value;
      }
      else
      {
        thycotic_error(0, "Invalid XML response : missing " + xml_stack[i], severity:ERROR_LOG);
        return NULL;
      }
    }
    else
    {
      j++;
      val_table = val_table_cache["children"][j];
      if (val_table)
      {
        continue;
      }
      else
      {
        thycotic_error(0, "Invalid XML response : missing " + xml_stack[i], severity:ERROR_LOG);
        return NULL;
      }
    }
  }

  items = val_table;
  creds = make_array();
  SecretIds = make_list();
  for (i=0;i<20;i++)
  {
    val_table = items;
    val_table = val_table["children"][i];
    if (isnull(val_table)) break;

    if (val_table["name"] == "SecretSummary")
    {
      foreach obj (val_table["children"])
      {
        if (obj["name"] == "SecretId")
        {
          SecretIds[max_index(SecretIds)] = obj["value"];
          break;
        }
      }
    }
    else
    {
      continue;
    }
  }

  return SecretIds;
}

##
# Gather the credentials from thycotic server
#
# @param [searchTerm:string] The SecretName
#
# @return array with username and password values
##
function thycotic_get_password(searchTerm)
{
  local_var res, req, creds, http_headers, http_status, value, i, j, PrivateKey,
  val_table, xml_stack, items, obj, FieldDisplayName, IsPassword, val_table_cache,
  PrivateKeyPassphrase, secretIds, secretId, creds_list;

  secretIds = thycotic_SearchSecretsByExposedValues(searchTerm:searchTerm, showDeleted:"false", showRestricted:"true", showPartialMatches:"false");

  creds_list = make_list();
  foreach secretId (secretIds)
  {
    req = '<?xml version="1.0" encoding="utf-8"?>
  <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
      <GetSecret xmlns="urn:thesecretserver.com">
        <token>'+THYCOTIC_TOKEN+'</token>
        <secretId>'+secretId+'</secretId>
        <loadSettingsAndPermissions>1</loadSettingsAndPermissions>
      </GetSecret>
    </soap:Body>
  </soap:Envelope>';

    http_headers = make_array("Content-Type","text/xml; charset=utf-8", "SOAPAction","urn:thesecretserver.com/GetSecret");
    res =  http_send_recv3(
      target       : THYCOTIC_TARGET,
      method       : "POST",
      item         : THYCOTIC_DIR+"webservices/sswebservice.asmx",
      data         : req,
      add_headers  : http_headers,
      port         : THYCOTIC_PORT,
      transport    : THYCOTIC_TRANSPORT,
      exit_on_fail : FALSE
    );
    http_disable_keep_alive();

    if (isnull(res))
    {
      thycotic_error(1,"Thycotic did not respond to request (GetSecret).",severity:ERROR_LOG);
      return NULL;
    }
    else if (THYCOTIC_DEBUG)
    {
      thycotic_log_debug(msg:"HTTP GetSecret STATUS ~ " + res[0] );
      thycotic_log_debug(msg:"HTTP GetSecret HEADERS ~ " + res[1] );
      thycotic_log_debug(msg:"HTTP GetSecret BODY ~ " + res[2] );
    }

    http_status = thycotic_ValidateResp(status_line:res[0]);
    if (http_status != 200)
    {
      thycotic_error(1,"Thycotic responded with " + res[0],severity:ERROR_LOG);
      return NULL;
    }

    val_table = xmlparse(res[2]);
    xml_stack = make_list("soap:Envelope","soap:Body","GetSecretResponse", "GetSecretResult", "Secret", "Items");
    i = 0; # index counter into xml_stack
    j = 0; # used to increase the counter in the list values
    while (TRUE)
    {
      if (val_table["name"] == xml_stack[i])
      {
        if (isnull(xml_stack[i+1])) break; # break out of the loop once we reach the last index value;

        val_table_cache = val_table; # used to cache the last position for indexing
        val_table = val_table["children"][j]; # change the table pointer to the child unit
        if (val_table)
        {
          j = 0; # if the index has matched then you need to reset the index values
          i++;
          continue; # move to the next index value;
        }
        else
        {
          thycotic_error(0, "Invalid XML response : missing " + xml_stack[i], severity:ERROR_LOG);
          return NULL;
        }
      }
      else
      {
        j++;
        val_table = val_table_cache["children"][j];
        if (val_table)
        {
          continue;
        }
        else
        {
          thycotic_error(0, "Invalid XML response : missing " + xml_stack[i], severity:ERROR_LOG);
          return NULL;
        }
      }
    }

    items = val_table;
    i = 0;
    creds = make_array();
    for (i=0;i<20;i++)
    {
      val_table = items;
      val_table = val_table["children"][i];
      if (isnull(val_table)) break;

      if (val_table["name"] == "SecretItem")
      {
        value = FieldDisplayName = IsPassword = PrivateKey = PrivateKeyPassphrase = NULL;
        foreach obj (val_table["children"])
        {
          if (obj["name"] == "Value") value = obj["value"];
          else if (obj["name"] == "FieldDisplayName") FieldDisplayName = obj["value"];
          else if (obj["name"] == "IsPassword") IsPassword = obj["value"];
        }

        if (FieldDisplayName == "Password" && IsPassword == "true") creds["password"] = value;
        if (FieldDisplayName == "Username") creds["username"] = value;
        if (FieldDisplayName == "Private Key Passphrase" && IsPassword == "true")  creds["PrivateKeyPassphrase"] = value;
      }
      else
      {
        continue;
      }
    }

    # download Private key
    if (thycotic_privatekey_enabled())
    {
      creds["PrivateKey"] = thycotic_DownloadFileAttachment(secretId:secretId);
    }

    creds_list[max_index(creds_list)] = creds;
  }

  return creds_list;
}

##
#
##
function thycotic_DownloadFileAttachment(secretId)
{
  local_var private_key,req,http_headers,res,http_status,val_table,xml_stack,
            i,j,val_table_cache,items,creds,obj;

  req = '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DownloadFileAttachment xmlns="urn:thesecretserver.com">
      <token>'+THYCOTIC_TOKEN+'</token>
      <secretId>'+secretId+'</secretId>
    </DownloadFileAttachment>
  </soap:Body>
</soap:Envelope>';

  http_headers = make_array("Content-Type","text/xml; charset=utf-8", "SOAPAction","urn:thesecretserver.com/DownloadFileAttachment");
  res =  http_send_recv3(
        target       : THYCOTIC_TARGET,
        method       : "POST",
        item         : THYCOTIC_DIR+"webservices/sswebservice.asmx",
        data         : req,
        add_headers  : http_headers,
        port         : THYCOTIC_PORT,
        transport    : THYCOTIC_TRANSPORT,
        exit_on_fail : FALSE
        );

  if (isnull(res))
  {
    thycotic_error(1,"Thycotic did not respond to request (DownloadFileAttachment).",severity:ERROR_LOG);
    return NULL;
  }
  else if (THYCOTIC_DEBUG)
  {
    thycotic_log_debug(msg:"HTTP GetSecret STATUS ~ " + res[0] );
    thycotic_log_debug(msg:"HTTP GetSecret HEADERS ~ " + res[1] );
    thycotic_log_debug(msg:"HTTP GetSecret BODY ~ " + res[2] );
  }

  http_status = thycotic_ValidateResp(status_line:res[0]);
  if (http_status != 200)
  {
    thycotic_error(1,"Thycotic responded with " + res[0],severity:ERROR_LOG);
    return NULL;
  }

  val_table = xmlparse(res[2]);
  xml_stack = make_list("soap:Envelope","soap:Body","DownloadFileAttachmentResponse");
  i = 0; # index counter into xml_stack
  j = 0; # used to increase the counter in the list values
  while (TRUE)
  {
    if (val_table["name"] == xml_stack[i])
    {
      if (isnull(xml_stack[i+1])) break; # break out of the loop once we reach the last index value;

      val_table_cache = val_table; # used to cache the last position for indexing
      val_table = val_table["children"][j]; # change the table pointer to the child unit
      if (val_table)
      {
        j = 0; # if the index has matched then you need to reset the index values
        i++;
        continue; # move to the next index value;
      }
      else
      {
        thycotic_error(0, "Invalid XML response : missing " + xml_stack[i], severity:ERROR_LOG);
        return NULL;
      }
    }
    else
    {
      j++;
      val_table = val_table_cache["children"][j];
      if (val_table)
      {
        continue;
      }
      else
      {
        thycotic_error(0, "Invalid XML response : missing " + xml_stack[i], severity:ERROR_LOG);
        return NULL;
      }
    }
  }

  items = val_table;
  i = 0;
  creds = make_array();
  for (i=0;i<20;i++)
  {
    val_table = items;
    val_table = val_table["children"][i];
    if (isnull(val_table)) break;

    if (val_table["name"] == "DownloadFileAttachmentResult")
    {
      private_key = NULL;
      foreach obj (val_table["children"])
      {
        if (obj["name"] == "FileAttachment") private_key = obj["value"];
      }
    }
    else
    {
      continue;
    }
  }

  return private_key;
}

#######################
## Private Functions ##
#######################

##
# Parse the Thycotic Secret Server URL into
# parts to be used.
#
# @param [url:string] On Thycotic admin->Configuration->General->Application Settings->Secret Server URL
#
# @return {ssl:BOOL, target:string, directory:string} || NULL on fail
##
function thycotic_parse_url(url)
{
  local_var val, directory, i , ret, target;
  directory = "";
  ret = make_array();

  val = split(sep:"/", url, keep:FALSE);
  if (max_index(val) < 2) return NULL;

  if (val[0] == "http:") ret["ssl"] = FALSE; #sslfalse
  else if (val[0] == "https:") ret["ssl"] = TRUE; #ssltrue
  else ret["ssl"] = NULL;

  if (val[2] =~ ":")
  {
    target = split(sep:":", val[2], keep:FALSE);
    ret["target"] = target[0];
    ret["port"] = target[1];
  }
  else
  {
    if (ret["ssl"]) ret["port"] = 443;
    else ret["port"] = 80;
    ret["target"] = val[2];
  }

  for (i=3;i<max_index(val);i++)
  {
    if (isnull(val[i])) break;
    directory += "/" + val[i];
  }
  ret["directory"] = directory += "/";

  return ret;
}

##
# Validate the HTTP status
#
# @param [status_line:string] the HTTP status line
#
# @return int status code or NULL if error or status_line does not
#             contain an HTTP status of 20x, 40x, or 50x
##
function thycotic_ValidateResp(status_line)
{
  local_var errorMsg;

  if (status_line =~ '^HTTP/1\\.[01] +200')
  {
    return 200;
  }
  else if (status_line =~ '^HTTP/1\\.[01] +40[0-9]')
  {
    thycotic_error(1,
               chomp(status_line) + " returned",
               severity:ERROR_LOG);

    return 400;
  }
  else if (status_line =~ '^HTTP/1\\.[01] +50[0-9]')
  {
    errorMsg = chomp(status_line) + " returned";

    thycotic_error(1,
               errorMsg,
               severity:ERROR_LOG);

    return 500;
  }
  else
  {
      thycotic_error(1,
                 chomp(status_line) + " returned",
                 severity:ERROR_LOG);
  }

  return NULL;
}

##################
## Example Demo ##
##################

##
# Demo on how to use thycotic
##
function thycotic_demo()
{
  local_var token, creds, init_ret;

  init_ret = thycotic_init(private_key:TRUE,
                           username:"admin",
                           password:"password",
                           organization:"",
                           domain:"",
                           secret_server_url:"http://<hostname>/SecretServer/",
                           ssl_verify:FALSE,
                           debug:TRUE);

  if (isnull(init_ret))
  {
    exit(0, thycotic_get_last_error());
  }

  token = thycotic_authenticate();
  creds = thycotic_get_password(searchTerm:"SSH key machine");
  dump_table(table:creds);

}
