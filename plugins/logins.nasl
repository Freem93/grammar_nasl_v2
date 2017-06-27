#TRUSTED 1bcf67c14bca287f4f276233e0825912844310caf2b2b688b125b23926647c2408103dc8fcbd09eae14354f8ded1e22e0b6bc9b2edc15d05686753483257bd2c48bdfc6751d8b428707095d4213bc39d46c520759b7c74eeca7d286334e81de1f1b826656f4ebcefc27cdd5f20fe232abf0814a7320eff661f79e5f3e64130dba1ebcab1844996d268691b1ad2c236dd1c5367a3e86dda513ada37eebb11fb94ef041cb1f23d915cbb82fb5da91e0342d0db8001fbfe1f66b3c903e062ccc12a9f290c70d0c3ccfee310f95cda17b40409b6771c83d39320af2b000ab988b75a96cc9d49de7cb6df9fe75e38090bda42fd215464aecc0f2d1a925424cff3b2473582c10d4ac6b84fdc3e3168ab8b967f4911a1768aeeaccc1157eaa6427c0efebe7aa51a0f1cc1db007c300c23aff0e0a74b51cce0b9fa7f7b6a04154c3b79cd98a2ef689b16c17e1a92816571b12272eb69fe9357a8a29e72e7e88abfe21354e6a5745243e24fa6d4f807f99622be837ebe19581b820ae30e75c8bf0c55764124537769b026c10f8d1c3364082240f0f274a8750305fbfa434c5b831e351180e476f303bb21307e2e608685bac930dee1ab965552f1587e524c3e90cbb3f84c37c3689acbd7879efa1975031e4a674e0b90de110aa8c50219c32acae62d015fba1a1cdf2d4f03975aff02aedba427895967d5103eb772476b4d15494bbc0588

#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

include("compat.inc");

global_var MAX_ADDITIONAL_SMB_LOGINS;
MAX_ADDITIONAL_SMB_LOGINS = 3;

if (description)
{
 script_id(10870);
 script_version("1.45");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/22");

 script_name(english:"Login configurations");
 script_summary(english:"Logins for HTTP, FTP, NNTP, POP2, POP3, IMAP, IPMI, and SMB.");

 script_set_attribute(attribute:"synopsis", value:
"Miscellaneous credentials.");
 script_set_attribute(attribute:"description", value:
"This plugin provides the username and password for common servers :

HTTP, FTP, NNTP, POP2, POP3, IMAP, IPMI, and SMB (NetBios).

Some plugins will use those logins when needed. If you do not fill
some logins, those plugins will not be able run.

This plugin does not do any security checks.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/04");

 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();

 script_category(ACT_SETTINGS);
 script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
 script_family(english:"Settings");

 script_add_preference(name:"HTTP account :", type:"entry", value:"");
 script_add_preference(name:"HTTP password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"NNTP account :", type:"entry", value:"");
 script_add_preference(name:"NNTP password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"FTP account :", type:"entry", value:"anonymous");
 script_add_preference(name:"FTP password (sent in clear) :", type:"password", value:"nessus@nessus.org");
 script_add_preference(name:"FTP writeable directory :", type:"entry", value: "/incoming");

 script_add_preference(name:"POP2 account :", type:"entry", value:"");
 script_add_preference(name:"POP2 password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"POP3 account :", type:"entry", value:"");
 script_add_preference(name:"POP3 password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"IMAP account :", type:"entry", value:"");
 script_add_preference(name:"IMAP password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"IPMI account :", type:"entry", value:"");
 script_add_preference(name:"IPMI password (sent in clear) :", type:"password", value:"");

 script_add_preference(name:"SMB account :", type:"entry", value:"");
 script_add_preference(name:"SMB password :", type:"password", value:"");
 script_add_preference(name:"SMB domain (optional) :", type:"entry", value:"");
 script_add_preference(name:"SMB password type :", type:"radio", value:"Password;LM Hash;NTLM Hash");

 for ( i = 1 ; i <= MAX_ADDITIONAL_SMB_LOGINS ; i ++ )
 {
  script_add_preference(name:"Additional SMB account (" + i + ") :", type:"entry", value:"");
  script_add_preference(name:"Additional SMB password (" + i + ") :", type:"password", value:"");
  script_add_preference(name:"Additional SMB domain (optional) (" + i + ") :", type:"entry", value:"");
 }

 if(defined_func("MD5")) script_add_preference(name:"Never send SMB credentials in clear text", type:"checkbox", value:"yes");
 if(defined_func("MD5")) script_add_preference(name:"Only use NTLMv2", type:"checkbox", value:"no");
 script_add_preference(name:"Only use Kerberos authentication for SMB", type:"checkbox", value:"no");
 script_dependencie("kerberos.nasl");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("ssl_funcs.inc");
include("cyberark.inc");
include("thycotic.inc");
include("spad_log_func.inc");

global_var logins_last_error, result_list;

logins_last_error = "";
result_list = make_list();

####
### Error Handling
####

##
# Log error messages
#
# @param [error:string] the error message to get logged
##
function logins_log_error(error)
{
  spad_log(message:error);
  logins_last_error = error;
}

##
# Return last error logged
##
function logins_get_last_error()
{
  return logins_last_error;
}

####
### Credential Values
####

##
# HTTP
##
function http_credential_setup()
{
  local_var http_login, http_password, userpass, userpass64, authstr;

  http_login = script_get_preference("HTTP account :");
  http_password = script_get_preference("HTTP password (sent in clear) :");
  if (http_login)
  {
   if(http_password)
   {
    set_kb_item(name:"http/login", value:string(http_login));
    set_kb_item(name:"http/password", value:string(http_password));

    userpass = http_login + ":" + http_password;
    userpass64 = base64(str:userpass);
    authstr = "Authorization: Basic " + userpass64;
    set_kb_item(name:"http/auth", value:authstr);
   }
  }

  return NULL;
}

##
# NNTP
##
function nntp_credential_setup()
{
  local_var nntp_login, nntp_password;

  # NNTP
  nntp_login = script_get_preference("NNTP account :");
  nntp_password = script_get_preference("NNTP password (sent in clear) :");
  if (nntp_login)
  {
   if(nntp_password)
   {
    set_kb_item(name:"nntp/login", value:nntp_login);
    set_kb_item(name:"nntp/password", value:nntp_password);
   }
  }
}

##
# FTP
##
function ftp_credential_setup()
{
  local_var ftp_login, ftp_password, ftp_w_dir;

  # FTP
  ftp_login = script_get_preference("FTP account :");
  ftp_password = script_get_preference("FTP password (sent in clear) :");
  ftp_w_dir = script_get_preference("FTP writeable directory :");
  if (!ftp_w_dir) ftp_w_dir=".";
  set_kb_item(name:"ftp/writeable_dir", value:ftp_w_dir);
  if(ftp_login)
  {
   if(ftp_password)
   {
    set_kb_item(name:"ftp/login", value:ftp_login);
    set_kb_item(name:"ftp/password", value:ftp_password);
   }
  }
}

##
# pop2
##
function pop2_credential_setup()
{
  local_var pop2_login, pop2_password;
  # POP2
  pop2_login = script_get_preference("POP2 account :");
  pop2_password = script_get_preference("POP2 password (sent in clear) :");
  if(pop2_login)
  {
   if(pop2_password)
   {
    set_kb_item(name:"pop2/login", value:pop2_login);
    set_kb_item(name:"pop2/password", value:pop2_password);
   }
  }
}

##
# POP3
##
function pop3_credential_setup()
{
  local_var pop3_login, pop3_password;

  pop3_login = script_get_preference("POP3 account :");
  pop3_password = script_get_preference("POP3 password (sent in clear) :");
  if(pop3_login)
  {
   if(pop3_password)
   {
    set_kb_item(name:"pop3/login", value:pop3_login);
    set_kb_item(name:"pop3/password", value:pop3_password);
   }
  }
}

##
# IMAP
##
function imap_credential_setup()
{
  local_var imap_login, imap_password;

  imap_login = script_get_preference("IMAP account :");
  imap_password = script_get_preference("IMAP password (sent in clear) :");
  if(imap_login)
  {
   if(imap_password)
   {
    set_kb_item(name:"imap/login", value:imap_login);
    set_kb_item(name:"imap/password", value:imap_password);
   }
  }
}

##
# IPMI
##
function ipmi_credential_setup()
{
  local_var ipmi_login, ipmi_password;

  ipmi_login = script_get_preference("IPMI account :");
  ipmi_password = script_get_preference("IPMI password (sent in clear) :");
  if(ipmi_login)
  {
    if(ipmi_password)
    {
     set_kb_item(name:"ipmi/login", value:ipmi_login);
     set_kb_item(name:"ipmi/password", value:ipmi_password);
    }
  }
}

##
# SMB
##
function smb_credential_setup()
{
  local_var smb_login, smb_password, smb_password_type, results_array,
  p_type, smb_domain, smb_ctxt, smb_ntv1, kdc_host, kdc_port,
  kdc_transport, kdc_use_tcp, j, i, smb_creds_prefix, smb_creds_postfix;

  j = 0;
  for ( i = 0 ; i <= MAX_ADDITIONAL_SMB_LOGINS || (defined_func("nasl_level") && nasl_level() >= 6000); i ++ )
  {
    # The loop condition will succeed if i is less than MAX_ADDITIONAL_SMB_LOGINS or the nessus version is greater
    # than 6.0 . This work with a check at the end of the loop to verify that if it is greater than 6.0 we break
    # on the first set of null credentials.

    if (i > 0)
    {
      smb_creds_prefix = "Additional ";
      smb_creds_postfix = " (" + i + ") :";
    }
    else
    {
      smb_creds_prefix = "";
      smb_creds_postfix = " :";
    }

    smb_login = script_get_preference(smb_creds_prefix+"SMB account"+smb_creds_postfix);
    smb_password = script_get_preference(smb_creds_prefix+"SMB password"+smb_creds_postfix);
    smb_domain = script_get_preference(smb_creds_prefix+"SMB domain (optional)"+smb_creds_postfix);

    # In nessus >= 6 there can be different kerberos settings for each set of creds.
    # if nessus < 6, data read by kerberos.nasl is used for all creds
    kdc_host = script_get_preference(smb_creds_prefix+"SMB Kerberos KDC"+smb_creds_postfix);
    kdc_port = script_get_preference(smb_creds_prefix+"SMB Kerberos KDC Port"+smb_creds_postfix);
    kdc_transport = script_get_preference(smb_creds_prefix+"SMB Kerberos KDC Transport"+smb_creds_postfix);
    kdc_use_tcp = FALSE;
    if (!kdc_transport || ";" >< kdc_transport || kdc_transport == "tcp")
      kdc_use_tcp = TRUE;

    # this new preferences will be introduced along with Nessus 6. in order to
    # maintain backwards compatibility with policies created under older scanners,
    # the password type set by the original preference (see SMB/password_type/0 above)
    # will be used as the default value for all additional SMB accounts
    if (script_get_preference(smb_creds_prefix+"SMB password type"+smb_creds_postfix))
      smb_password_type = script_get_preference(smb_creds_prefix+"SMB password type"+smb_creds_postfix);
    else
      smb_password_type = "";

    if ("Password" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"Password");
      p_type = 0;
    }
    else if ("NTLM Hash" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"NTLM Hash");
      p_type = 2;
    }
    else if ("LM Hash" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"LM Hash");
      p_type = 1;
    }
    else if ("CyberArk" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"CyberArk");
      smb_password = cyberark_smb_get_password(smb_login:smb_login, smb_domain:smb_domain, prefix:smb_creds_prefix, postfix:smb_creds_postfix);
      p_type = 0;
    }
    else if ("Thycotic" >< smb_password_type)
    {
      set_kb_item(name:"target/auth/method", value:"Thycotic");
      smb_password = thycotic_smb_get_password(account:smb_login, prefix:smb_creds_prefix, postfix:smb_creds_postfix);
      p_type = 0;
    }
    else
    {
      set_kb_item(name:"target/auth/method", value:"None");
      p_type = 0;
    }

    results_array = make_array();

    if ( smb_login && smb_password )
    {
      results_array["SMB/login_filled/" + j] = smb_login;
      results_array["SMB/password_filled/" + j] = smb_password;
      results_array["SMB/domain_filled/" + j] = smb_domain;
      results_array["SMB/password_type_filled/" + j] = p_type;

      if (kdc_host && kdc_port)
      {
        results_array["SMB/kdc_hostname_filled/" + j] = kdc_host;
        results_array["SMB/kdc_port_filled/" + j] = int(kdc_port);
        results_array["SMB/kdc_use_tcp_filled/" + j] = kdc_use_tcp;
      }
      result_list[j] = results_array;
      j ++;
    }
    else if (i >= MAX_ADDITIONAL_SMB_LOGINS)
    {
      # Break at the first null credential that is above the max count of 3 for any version
      # of nessus. This is important for nessus versions greater than 6.0 .
      break;
    }

  }

  smb_insert_data();
}

##
# SMB insert data gathered
##
function smb_insert_data()
{
  local_var rl, smbi;

  foreach rl (result_list)
  {
    foreach smbi (keys(rl))
    {
      set_kb_item(name:smbi , value:rl[smbi]);
    }
  }
}

##
# SMB : thycotic get password
##
function thycotic_smb_get_password(account, prefix, postfix)
{
  local_var thycotic_token, thycotic_creds, thycotic_cred, thycotic_init_ret, thycotic_username, thycotic_password,
            thycotic_organization, thycotic_domain, thycotic_secret_server_url,
            thycotic_ssl_verify, thycotic_secretId, password, thycotic_secret_name;

  thycotic_secret_name = script_get_preference(prefix+"SMB Thycotic Secret Name"+postfix); # secretId of the current credential
  # secret server url Admin->Configuration->General->Application Settings-> Secret Server URL
  thycotic_secret_server_url = script_get_preference(prefix+"SMB Thycotic Secret Server URL"+postfix);
  thycotic_username = script_get_preference(prefix+"SMB Thycotic Login Name"+postfix); # Thycotic username
  thycotic_password = script_get_preference(prefix+"SMB Thycotic Password"+postfix); # Thycotic password
  thycotic_organization = script_get_preference(prefix+"SMB Thycotic Organization"+postfix); #Thycotic organization (optional)
  thycotic_domain = script_get_preference(prefix+"SMB Thycotic Domain"+postfix); # Thycotic domain (optional)
  thycotic_ssl_verify = script_get_preference(prefix+"SMB Thycotic SSL verify"+postfix); # ssl verify setup?
  password = NULL;

  if (isnull(thycotic_secret_name))
  {
    logins_log_error(error:'Thycotic Error : SMB Thycotic Secret Name missing.');
    return NULL;
  }
  else if (isnull(thycotic_secret_server_url))
  {
    logins_log_error(error:'Thycotic Error : SMB Thycotic Secret Server URL missing.');
    return NULL;
  }
  else if (isnull(thycotic_username))
  {
    logins_log_error(error:'Thycotic Error : SMB Thycotic Login Name missing.');
    return NULL;
  }
  else if (isnull(thycotic_password))
  {
    logins_log_error(error:'Thycotic Error : SMB Thycotic Password missing.');
    return NULL;
  }

  if (thycotic_ssl_verify == "yes") thycotic_ssl_verify = TRUE;
  else thycotic_ssl_verify = FALSE;

  thycotic_init_ret = thycotic_init(username:thycotic_username,
                           password:thycotic_password,
                           organization:thycotic_organization,
                           domain:thycotic_domain,
                           secret_server_url:thycotic_secret_server_url,
                           ssl_verify:thycotic_ssl_verify);

  if (isnull(thycotic_init_ret))
  {
    logins_log_error(error:'Thycotic Error : ' + thycotic_get_last_error());
    return NULL;
  }
  else
  {
    thycotic_token = thycotic_authenticate();
    if (isnull(thycotic_token))
    {
      logins_log_error(error:'Thycotic Error : Failed to authenticate to Thycotic.');
      return NULL;
    }

    # Search for all matching Secret Name
    thycotic_creds = thycotic_get_password(searchTerm:thycotic_secret_name);
    if (isnull(thycotic_creds))
    {
      logins_log_error(error:'Thycotic Error : Failed to gather credentials from Thycotic for account (' + account + ').');
      return NULL;
    }
  }

  # Cycle through all Secret Names that match
  foreach thycotic_cred (thycotic_creds)
  {
    # match on the first username supplied
    if (account == thycotic_cred["username"])
    {
      password = thycotic_cred["password"];
      break;
    }
  }

  if (isnull(password))
  {
    # If no response matched both the Secret Name and the account name trigger an error.
    logins_log_error(error:'Thycotic Error : The account username '+account+' does not match the one gathered from Thycotic.');
    return NULL;
  }

  return password;
}

##
# SMB : Cyberark Get Password
##
function cyberark_smb_get_password(smb_login, smb_domain, prefix, postfix)
{
  local_var cyberark_host,cyberark_port,cyberark_username,cyberark_password,cyberark_ssl,
  cyberark_safe,cyberark_appid,cyberark_folder,cyberark_policyid,cyberark_url,
  cyberark_ssl_verify,host_ip,parameters,cyberark_creds,smb_password,error_stack,account_type,act;

  cyberark_host = script_get_preference(prefix+"SMB CyberArk Host"+postfix);
  cyberark_port = script_get_preference(prefix+"SMB CyberArk Port"+postfix);
  cyberark_username = script_get_preference(prefix+"SMB CyberArk Username"+postfix);
  cyberark_password = script_get_preference(prefix+"SMB CyberArk Password"+postfix);
  cyberark_ssl = script_get_preference(prefix+"SMB CyberArk SSL"+postfix);
  cyberark_ssl_verify = script_get_preference(prefix+"SMB CyberArk Verify SSL Certificate"+postfix);
  cyberark_safe = script_get_preference(prefix+"SMB CyberArk Safe"+postfix);
  cyberark_appid = script_get_preference(prefix+"SMB CyberArk AppId"+postfix);
  cyberark_folder = script_get_preference(prefix+"SMB CyberArk Folder"+postfix);
  cyberark_policyid = script_get_preference(prefix+"SMB CyberArk PolicyId"+postfix);
  cyberark_url = script_get_preference(prefix+"SMB CyberArk URL"+postfix);

  if (strlen(ereg_replace(pattern:"([^ ]*) *$", string:cyberark_username, replace:"\1")) == 0)
    cyberark_username  = NULL;

  if (strlen(ereg_replace(pattern:"([^ ]*) *$", string:cyberark_password, replace:"\1")) == 0)
    cyberark_password = NULL;

  if (cyberark_ssl == "yes") cyberark_ssl = TRUE;
  else cyberark_ssl = FALSE;

  if (cyberark_ssl_verify == "yes") cyberark_ssl_verify = TRUE;
  else cyberark_ssl_verify = FALSE;

  account_type = cark_init(debug:FALSE, # debugging output option
            target:cyberark_host,
            domain:smb_domain,
            port:cyberark_port,
            ssl:cyberark_ssl,
            ssl_verify:cyberark_ssl_verify,
            username:cyberark_username,
            password:cyberark_password,
            cark_url:cyberark_url
            );

  foreach act (account_type)
  {
    parameters = make_array(
        "Username",smb_login,
        "PolicyID",cyberark_policyid,
        "Safe",cyberark_safe,
        "AppID",cyberark_appid,
        "Folder",cyberark_folder,
        "Address",act,
        "Reason","NESSUS"
        );

    cyberark_creds = cark_get_password(parameters:parameters);

    if (!isnull(cyberark_creds)) break;
    else logins_log_error(error:'\n Cyberark Error : unable to obtain creds using the address "' +act+ '".');
  }

  if (isnull(cyberark_creds))
  {
    logins_log_error(error:'\n Cyberark Error : ' + cark_get_last_error());
  }
  else
  {
    if (!isnull(cyberark_creds["Password"]))
    {
      smb_password = cyberark_creds["Password"];
    }
    else
    {
      logins_log_error(error:'\n Null password : ' + cark_get_last_error());
    }
  }

  return smb_password;
}

http_credential_setup();
nntp_credential_setup();
ftp_credential_setup();
pop2_credential_setup();
pop3_credential_setup();
imap_credential_setup();
ipmi_credential_setup();
smb_credential_setup();
