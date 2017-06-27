#TRUSTED a206fd8ed4ad3eab070bb49bb822e91d0cff88b7be63f3d52194b5aef6d9f67c2deaa7762d45e317e9a885f69635db7236bb0ad4e340f149520cc8d7ee6be71e0209e120eb02b53f1631d6798b6a918156535fa1966681d646083a440b42a8a35cdb5934e4d68652d79c65b39da0ea1abca4671911dcda3d97495fe0652f48f76bddb661c6d0c5ae73c66b0b5e6ff9d848f8c183d64f40297f65a13452dc0ed07374a561fb680b1dd3bd839b4b235dfc0fc174967139c169512d52bcfdd0b7dc01832ab826d0ec93d899ca61c8676de1ba8da87d80c7043c2cf18a77c908c4686b6ad3f4fb606f49cfaab58884e5303bb15eb9dc6de5e65c87c4342682c2ee92ff18939d2780e4986d10f0ae127b85c982cd874ffc5ed1c61098b10d80fbe00e613241fe506b6d994dbe01bada65e9e064df87a689ec064e0b51180622e3f1e40707f73dade388cec0a0dcca7caec86188719982d752bccc8e74f020a80ea46eaeabf468079a89aa9e69d4206d35ba32c39a9deb2e14abaa9e936734d671bb7fb89cbd9a942ea3e8c7265b0d68a28fdad321e3450a2bbb5684112702a01ce0a57143c979cd7471fbce2f68f51855af9a1e33cd127804f02f6761b95c5c73e75f0bf0b19073f8d293959a457141a87d984b21f7220dd516b3a7277b0516a5bd47cccceda016930edf76ce00b5abf509334f7376a40734a9d10fe9a0766223c164

#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

if ( ! defined_func("bn_random") ) exit(0);
include("compat.inc");

if(description)
{
 script_id(14273);
 script_version ("1.47");
 script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/22");

 script_name(english:"SSH settings");
 script_summary(english:"Set SSH keys & user name to perform local security checks.");

 script_set_attribute(attribute:"synopsis", value:
"This plugin configures the SSH subsystem.");
 script_set_attribute(attribute:"description", value:
"This plugin initializes the SSH credentials as set by the user.

To set the credentials, edit your scan policy and go to the section
'Credentials'.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/15");

 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();

 script_family(english:"Settings");
 script_category(ACT_INIT);

 script_copyright(english:"Copyright (C) 2004-2017 Tenable Network Security, Inc.");

 if (defined_func("bn_random"))
 {
   script_add_preference(name:"SSH user name : ",
                       type:"entry",
                       value:"root");
   script_add_preference(name:"SSH password (unsafe!) : ",
                       type:"password",
                       value:"");
   script_add_preference(name:"SSH public key to use : ",
                       type:"file",
                       value:"");
  script_add_preference(name:"SSH private key to use : ",
                       type:"file",
                       value:"");
  script_add_preference(name:"Passphrase for SSH key : ",
                       type:"password",
                       value:"");
  script_add_preference(name:"Elevate privileges with : ",
                       type:"radio",
                       value:"Nothing;sudo;su;su+sudo;dzdo;pbrun;Cisco 'enable'");
  script_add_preference(name:"Privilege elevation binary path (directory) : ",
                       type:"entry",
                       value:"");
  script_add_preference(name:"su login : ",
                       type:"entry",
                       value:"");
  script_add_preference(name:"Escalation account : ",
                       type:"entry",
                       value:"root");
  script_add_preference(name:"Escalation password : ",
                       type:"password",
                       value:"");
  script_add_preference(name:"SSH known_hosts file : ",
                       type:"file",
                       value:"");
  script_add_preference(name:"Preferred SSH port : ",
                       type:"entry",
                       value:"22");
  script_add_preference(name:"Client version : ",
                       type:"entry",
                       value:"OpenSSH_5.0");

  for ( i = 1 ; i <= 5 ; i ++ )
  {
   script_add_preference(name:strcat("Additional SSH user name (", i, ") : "),
                       type:"entry",
                       value:"");
   script_add_preference(name:strcat("Additional SSH password (", i, ") : "),
                       type:"password",
                       value:"");
  }
 }

 exit(0);
}
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("ssl_funcs.inc");
include("cyberark.inc");
include("ssh_func.inc");
include("thycotic.inc");

global_var ssh_settings_last_error;

ssh_settings_last_error = "";

##
# Determines if the given hostname patterns match the current target
#
# The man page for sshd(8) says:
#
# "Hostnames is a comma-separated list of patterns (`*' and `?' act as
#  wildcards); each pattern in turn is matched against the canonical host
#  name (when authenticating a client) or against the user-supplied name
#  (when authenticating a server).  A pattern may also be preceded by `!' to
#  indicate negation: if the host name matches a negated pattern, it is not
#  accepted (by that line) even if it matched another pattern on the line.
#  A hostname or address may optionally be enclosed within `[' and `]'
#  brackets then followed by `:' and a non-standard port number"
#
# @anonparam patterns a comma delimited list of patterns
# @return TRUE if the IP or hostname of the current target matches any patterns,
#         FALSE otherwise
##
function patterns_match_this_host()
{
  local_var patterns, port, pattern, match, negated, target_ip, target_hostname;
  patterns = split(_FCT_ANON_ARGS[0], sep:',', keep:FALSE);
  port = _FCT_ANON_ARGS[1];
  if (isnull(port)) port = 22;

  match = FALSE;
  target_ip = get_host_ip();
  target_hostname = get_host_name();

  foreach pattern (patterns)
  {
    negated = FALSE;
    if (pattern[0] == '!')
    {
      negated = TRUE;
      pattern = substr(pattern, 1);
    }

    if (pattern =~ "^\[.*\]:[0-9]+") # key with non-standard port, e.g., [ssh.example.net]:2222
    {
      if (
        pattern == strcat('[', target_ip, ']:', port) ||
        pattern == strcat('[', target_hostname, ']:', port)
      )
      {
        if (negated) return FALSE; # a negated pattern takes precedence over all other patterns
        match = TRUE;
      }
    }
    else
    {
      pattern = str_replace(string:pattern, find:'.', replace:"\.");
      pattern = str_replace(string:pattern, find:'*', replace:".*");
      pattern = str_replace(string:pattern, find:'?', replace:".");
      pattern = '^' + pattern + '$';

      if (
        ereg(string:target_ip, pattern:pattern) ||
        ereg(string:target_hostname, pattern:pattern, icase:TRUE)
      )
      {
        if (negated) return FALSE; # a negated pattern takes precedence over all other patterns
        match = TRUE;
      }
    }
  }

  return match;
}

##
# Log the errors associated with this plugin
##
function ssh_settings_log_error(error)
{
  spad_log(message:error);
  ssh_settings_last_error = error;
}

##
# Get last error logged
##
function ssh_settings_get_last_error()
{
  return ssh_settings_last_error;
}

##
# Get cyberark password
#
# @param [account:string] the account to gather the password
# @param [ssh_prefix:string] used to prefix for additional values
# @param [ssh_postfix:string] used to postfix for additional values
#
# @return string password value
##
function cyberark_get_ssh_password(account, ssh_prefix, ssh_postfix)
{
  local_var cyberark_port, cyberark_username, cyberark_password, cyberark_safe, cyberark_appid, 
    cyberark_folder, cyberark_ssl, cyberark_ssl_verify, cyberark_policyid, parameters,
    cyberark_creds, password, cyberark_host, account_type, act, cyberark_url;

  cyberark_host       =  script_get_preference(ssh_prefix+"SSH CyberArk Host"+ssh_postfix);
  cyberark_port       =  script_get_preference(ssh_prefix+"SSH CyberArk Port"+ssh_postfix);
  cyberark_username   =  script_get_preference(ssh_prefix+"SSH CyberArk Username"+ssh_postfix);
  cyberark_password   =  script_get_preference(ssh_prefix+"SSH CyberArk Password"+ssh_postfix);
  cyberark_safe       =  script_get_preference(ssh_prefix+"SSH CyberArk Safe"+ssh_postfix);
  cyberark_appid      =  script_get_preference(ssh_prefix+"SSH CyberArk AppId"+ssh_postfix);
  cyberark_folder     =  script_get_preference(ssh_prefix+"SSH CyberArk Folder"+ssh_postfix);
  cyberark_ssl        =  script_get_preference(ssh_prefix+"SSH CyberArk SSL"+ssh_postfix);
  cyberark_ssl_verify =  script_get_preference(ssh_prefix+"SSH CyberArk Verify SSL Certificate"+ssh_postfix);
  cyberark_policyid   =  script_get_preference(ssh_prefix+"SSH CyberArk PolicyId"+ssh_postfix);
  cyberark_url        =  script_get_preference(ssh_prefix+"SSH CyberArk URL"+ssh_postfix);

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
                "Username",account,
                "PolicyID",cyberark_policyid,
                "Safe",cyberark_safe,
                "AppID",cyberark_appid,
                "Folder",cyberark_folder,
                "Address",act,
                "Reason","NESSUS"
                );

    cyberark_creds = cark_get_password(parameters:parameters);
    if (!isnull(cyberark_creds)) break;
  }

  if (isnull(cyberark_creds))
  {
    ssh_settings_log_error(error:'CyberArk Error : ' + cark_get_last_error());
    return NULL;
  }
  else
  {
    if (!isnull(cyberark_creds["Password"]))
    {
      password = cyberark_creds["Password"];
    }
    else
    {
      ssh_settings_log_error(error:'CyberArk Null Password : ' + cark_get_last_error());
      password = NULL;
    }
  }

  return password;
}

##
# Get cyberark elevate password
#
# @param [objname:string] cyberark account details name value
# @param [ssh_prefix:string] used to prefix for additional values
# @param [ssh_postfix:string] used to postfix for additional values
#
# @return string password value
##
function cyberark_get_ssh_elevate_password(objname, ssh_prefix, ssh_postfix)
{
  local_var cyberark_port, cyberark_username, cyberark_password, cyberark_safe, cyberark_appid, 
    cyberark_folder, cyberark_ssl, cyberark_ssl_verify, cyberark_policyid, parameters,
    cyberark_creds, password, cyberark_host, account_type, act;

  cyberark_host       =  script_get_preference(ssh_prefix+"SSH CyberArk Host"+ssh_postfix);
  cyberark_port       =  script_get_preference(ssh_prefix+"SSH CyberArk Port"+ssh_postfix);
  cyberark_username   =  script_get_preference(ssh_prefix+"SSH CyberArk Username"+ssh_postfix);
  cyberark_password   =  script_get_preference(ssh_prefix+"SSH CyberArk Password"+ssh_postfix);
  cyberark_appid      =  script_get_preference(ssh_prefix+"SSH CyberArk AppId"+ssh_postfix);
  cyberark_ssl        =  script_get_preference(ssh_prefix+"SSH CyberArk SSL"+ssh_postfix);
  cyberark_ssl_verify =  script_get_preference(ssh_prefix+"SSH CyberArk Verify SSL Certificate"+ssh_postfix);
  cyberark_policyid   =  script_get_preference(ssh_prefix+"SSH CyberArk PolicyId"+ssh_postfix);

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
            port:cyberark_port,
            ssl:cyberark_ssl,
            ssl_verify:cyberark_ssl_verify,
            username:cyberark_username,
            password:cyberark_password
            );

  foreach act (account_type)
  {
    parameters = make_array(
                "AppID",cyberark_appid,
                "Object", objname,
                "Reason","NESSUS"
                );

    cyberark_creds = cark_get_password(parameters:parameters);
    if (!isnull(cyberark_creds)) break;
  }
  if (isnull(cyberark_creds))
  {
    ssh_settings_log_error(error:'CyberArk Error : ' + cark_get_last_error());
    return NULL;
  }
  else
  {
    if (!isnull(cyberark_creds["Password"]))
    {
      password = cyberark_creds["Password"];
    }
    else
    {
      ssh_settings_log_error(error:'CyberArk Null Password : ' + cark_get_last_error());
      password = NULL;
    }
  }

  return password;
}


##
# Gather the SSH password from thycotic server
#
# @param [account:string] the account name to look up
# @param [ssh_prefix:string] used to prefix for additional values
# @param [ssh_postfix:string] used to postfix for additional values
#
# @return ??
##
function thycotic_get_ssh_password(account, ssh_prefix, ssh_postfix)
{
  local_var thycotic_token, thycotic_creds, thycotic_cred, thycotic_init_ret, thycotic_username, thycotic_password,
            thycotic_organization, thycotic_domain, thycotic_secret_server_url, thycotic_port, thycotic_ssl,
            thycotic_ssl_verify, thycotic_secretId, password, thycotic_secret_name, debug_report, thycotic_pk;

  #gather parameter
  thycotic_secret_name = script_get_preference(ssh_prefix+"SSH Thycotic Secret Name"+ssh_postfix); # secretId of the current credential
  thycotic_secret_server_url = script_get_preference(ssh_prefix+"SSH Thycotic Secret Server URL"+ssh_postfix);
  # ^ secret server url Admin->Configuration->General->Application Settings-> Secret Server URL
  thycotic_username = script_get_preference(ssh_prefix+"SSH Thycotic Login Name"+ssh_postfix); # Thycotic username
  thycotic_password = script_get_preference(ssh_prefix+"SSH Thycotic Password"+ssh_postfix); # Thycotic password
  thycotic_organization = script_get_preference(ssh_prefix+"SSH Thycotic Organization"+ssh_postfix); #Thycotic organization (optional)
  thycotic_domain = script_get_preference(ssh_prefix+"SSH Thycotic Domain"+ssh_postfix); # Thycotic domain (optional)
  thycotic_ssl_verify = script_get_preference(ssh_prefix+"SSH Thycotic Verify SSL Certificate"+ssh_postfix); # ssl verify setup?

  password = NULL;

  if (thycotic_ssl_verify == "yes") thycotic_ssl_verify = TRUE;
  else thycotic_ssl = FALSE;

  thycotic_init_ret = thycotic_init(username:thycotic_username,
                           password:thycotic_password,
                           organization:thycotic_organization,
                           domain:thycotic_domain,
                           secret_server_url:thycotic_secret_server_url,
                           ssl_verify:thycotic_ssl_verify,
                           private_key:TRUE);

  if (isnull(thycotic_init_ret))
  {
    ssh_settings_log_error(error:'Thycotic Error : ' + thycotic_get_last_error());
    return NULL;
  }
  else
  {
    thycotic_token = thycotic_authenticate();
    if (isnull(thycotic_token))
    {
      ssh_settings_log_error(error:'Thycotic Error : Failed to authenticate to Thycotic.');
      return NULL;
    }

    thycotic_creds = thycotic_get_password(searchTerm:thycotic_secret_name);
    if (isnull(thycotic_creds))
    {
      ssh_settings_log_error(error:'Thycotic Error : Failed to gather credentials from Thycotic for account (' + account + ').');
      return NULL;
    }
  }

  return thycotic_creds;
}

##
# Gather ssh settings from the UI and store them in the kb for access
#
# @return list of the ssh creds
##
function ssh_settings_get_settings()
{
  local_var client_ver, pref_port, i, j, jindex, ssh_prefix, ssh_postfix, ssh_pub_key_cert,
    account,private_key,passphrase,password,kdc,kdc_port,kdc_transport,realm,sudo,result_list,
    su_login,sudo_path,root,sudo_password,cyberark_host,cyberark_creds,result_array,CiscoEnable,
    cert, ssh_pw_warning, thycotic_creds, thycotic_cred, cyberark_name;

  ###
  ## Begin global preferences
  ###
  CiscoEnable = FALSE;
  client_ver  = script_get_preference("Client version : ");
  pref_port = script_get_preference("Preferred SSH port : ");
  result_list = make_list();

  ##
  # j is used to keep track of the current successfully gathered creds to
  # insert into the kb. The kb needs to be inserted starting with no counter
  # and increase in numerical order string at 0 and not skipping any values.
  # kb first  /SSH/value/test = X
  # kb second /SSH/value/0/test = X
  # kb third  /SSH/value/1/test = X
  ##
  j = 0;

  ##
  # Loop through all credentials and store the values in an array
  # to be indexed later for scan storage.
  # The array is used instead of direct insert to be able to easily
  # access the values for any normalization or generic manipulation.
  ##
  for (i=0;i<10;i++)
  {
    if (i > 0)
    {
      ssh_prefix = "Additional "; # additional creds add the "Additional" prefix
      ssh_postfix = " ("+i+") : "; # additional creds are followed by an index value

      # The additional instances of the public key/cert will use
      # a different string parameter displayed here.
      ssh_pub_key_cert = "Additional SSH certificate to use ("+i+") : ";

      # additional passwords do not have the unsafe warning
      ssh_pw_warning =  "";
    }
    else
    {

      ssh_prefix = ""; # first instance does not have a prefix
      ssh_postfix = " : "; # there is no index into the first instance of parameters

      # The first instance of the public key/cert will use
      # a different string parameter displayed here.
      ssh_pub_key_cert = "SSH public key to use : ";

      # The first instance of the password field has the unsafe title
      ssh_pw_warning =  " (unsafe!)";
    }

    if (j > 0)
    {
      # create the index value to be stored in the KB. The value is j-1 because we start
      # counting kb index values at 0.
      jindex = "/"+(j-1)+"/"; # define the index value into the KB
    }
    else
    {
      # The first index value will always be stored without an int index
      jindex = "/"; # define no index into the KB
    }

    # gather username
    account =  script_get_preference(ssh_prefix+"SSH user name"+ssh_postfix);
    if ( strlen(account) < 1 )
    {
      if ( COMMAND_LINE ) break;
      if ( i <= 5 ) continue;
      else break;
    }

    cert = script_get_preference_file_content(ssh_pub_key_cert);
    private_key = script_get_preference_file_content(ssh_prefix+"SSH private key to use"+ssh_postfix);
    passphrase  = script_get_preference(ssh_prefix+"Passphrase for SSH key"+ssh_postfix);
    password = script_get_preference(ssh_prefix+"SSH password"+ssh_pw_warning+ssh_postfix);
    kdc = script_get_preference(ssh_prefix+"Kerberos KDC"+ssh_postfix);
    kdc_port = script_get_preference(ssh_prefix+"Kerberos KDC Port"+ssh_postfix);
    kdc_transport = script_get_preference(ssh_prefix+"Kerberos KDC Transport"+ssh_postfix);
    realm = script_get_preference(ssh_prefix+"Kerberos Realm"+ssh_postfix);

    # For additional elevate priv only attempt to read the new privilege elevation preferences when running at Nessus 6 compatibility or later.
    # on scanners running at older than Nessus 6 compatibility, the values read from the original privilege elevation preferences above will be reused
    # a policy is using the new Nessus 6 preferences if the following one is present
    if (script_get_preference(ssh_prefix+"Elevate privileges with"+ssh_postfix))
    {
      sudo = script_get_preference(ssh_prefix+"Elevate privileges with"+ssh_postfix);
      su_login = script_get_preference(ssh_prefix+"su login"+ssh_postfix);
      sudo_path = script_get_preference(ssh_prefix+"Privilege elevation binary path (directory)"+ssh_postfix);
      root = script_get_preference(ssh_prefix+"Escalation account"+ssh_postfix);
      if (root !~ "^[A-Za-z][A-Za-z0-9_.-]+$") root = "root";
      sudo_password = script_get_preference(ssh_prefix+"Escalation password"+ssh_postfix);
    }

    #
    # Gather cyberark creds
    #
    if (script_get_preference(ssh_prefix+"SSH CyberArk Host"+ssh_postfix))
    {
      cyberark_creds = cyberark_get_ssh_password(account:account, ssh_prefix:ssh_prefix, ssh_postfix:ssh_postfix);

      # detect if cyberark returned a private key or a password or failed with null
      if (isnull(cyberark_creds))
      {
        continue;
      }
      else if (cyberark_creds  =~ "BEGIN (RSA|DSA) PRIVATE KEY")
      {
        private_key = cyberark_creds;
      }
      else
      {
        password = cyberark_creds;
      }

      if (script_get_preference(ssh_prefix+"CyberArk elevate privileges with"+ssh_postfix))
      {
        sudo = script_get_preference(ssh_prefix+"CyberArk elevate privileges with"+ssh_postfix);
        su_login = script_get_preference(ssh_prefix+"su login"+ssh_postfix);
        sudo_path = script_get_preference(ssh_prefix+"Privilege elevation binary path (directory)"+ssh_postfix);
        root = script_get_preference(ssh_prefix+"Escalation account"+ssh_postfix);
        if (root !~ "^[A-Za-z][A-Za-z0-9_.-]+$") root = "root";
        cyberark_name = script_get_preference(ssh_prefix+"CyberArk Account Details Name"+ssh_postfix);

        sudo_password = cyberark_get_ssh_elevate_password(objname:cyberark_name, ssh_prefix:ssh_prefix, ssh_postfix:ssh_postfix);

      }

    }

    #
    # Gather Thycotic Creds
    #
    if (script_get_preference(ssh_prefix+"SSH Thycotic Secret Server URL"+ssh_postfix))
    {
      thycotic_creds = thycotic_get_ssh_password(account:account, ssh_prefix:ssh_prefix, ssh_postfix:ssh_postfix);

      if (isnull(thycotic_creds))
      {
        ssh_settings_log_error(error:'Thycotic Error : Failed to obtain password from thycotic_get_ssh_password.');
        continue;
      }
      else
      {

        foreach thycotic_cred (thycotic_creds)
        {
          if (account == thycotic_cred["username"])
          {
            if ( !isnull(thycotic_cred["PrivateKey"]) )
            {
              private_key = base64_decode(str:thycotic_cred["PrivateKey"]);
              if ( !(private_key =~ "BEGIN (RSA|DSA) PRIVATE KEY") )
              {
                ssh_settings_log_error(error:'Thycotic Error : The private key obtained is not in openssh format.');
                break;
              }

              if (strlen(thycotic_cred["PrivateKeyPassphrase"]) > 0)
              {
                passphrase = thycotic_cred["PrivateKeyPassphrase"];
              }
            }
            else
            {
              if (isnull(thycotic_cred["password"]))
              {
                ssh_settings_log_error(error:'Thycotic Error : No password available for supplied machine.');
                break;
              }

              password = thycotic_cred["password"];
            }

            break;
          }
        }

        if (isnull(password) && isnull(private_key))
        {
          ssh_settings_log_error(error:'Unable to obtain credentials from Thycotic.');
          continue;
        }

      }
    }

    ##
    # USE THIS SPACE TO EXPAND NEW PASSWORD MANAGERS
    ##

    # if no credentials are set continue to the next instance
    if (isnull(password) && isnull(private_key))
    {
      #no credentials set for user account
      ssh_settings_log_error(error:'No credentials set for account (' + account + ')');
      continue;
    }

    # storage for credentials information
    result_array = make_array();
    if (j == 0)
    {
      # these values are single instance storage value or legacy values and only need set one time.

      if (!isnull(cert)) result_array["Secret/SSH/publickey"] = cert; #less than nessus 6 only
      if (!isnull(kdc)) result_array["Secret/kdc_hostname"] = kdc; #less than nessus 6 only
      if (!isnull(kdc_port)) result_array["Secret/kdc_port"] = int(kdc_port); #less than nessus 6 only
      if (!kdc_transport || ";" >< kdc_transport || kdc_transport == "tcp")
        result_array["Secret/kdc_use_tcp"] = TRUE; #less than nessus 6 only

      if (!isnull(client_ver)) result_array["SSH/clientver"] = client_ver; #global
      if (!isnull(pref_port) && int(pref_port) ) result_array["Secret/SSH/PreferredPort"] = int(pref_port); # global
    }

    if (!isnull(account)) result_array["Secret/SSH"+jindex+"login"] = account;
    if (!isnull(root)) result_array["Secret/SSH"+jindex+"root"] = root;
    if (!isnull(cert)) result_array["Secret/SSH"+jindex+"certificate"] = cert;
    if (!isnull(private_key)) result_array["Secret/SSH"+jindex+"privatekey"] = hexstr(private_key);
    if (!isnull(passphrase)) result_array["Secret/SSH"+jindex+"passphrase"] = passphrase;
    if (!isnull(password)) result_array["Secret/SSH"+jindex+"password"] = password;

    # save Kerberos preferences
    if (kdc && kdc_port && realm)
    {
      result_array["Secret/SSH"+jindex+"kdc_hostname"] = kdc;
      result_array["Secret/SSH"+jindex+"kdc_port"] = int(kdc_port);
      result_array["Kerberos/SSH"+jindex+"realm"] = realm;

      if (!kdc_transport || ";" >< kdc_transport || kdc_transport == "tcp")
        result_array["Kerberos/SSH"+jindex+"kdc_use_tcp"] = TRUE;
    }

    CiscoEnable = FALSE;
    if ( sudo == "sudo" ) result_array["Secret/SSH"+jindex+"sudo"] = SU_SUDO;
    else if ( sudo == "su" ) result_array["Secret/SSH"+jindex+"sudo"] = SU_SU;
    else if ( sudo == "su+sudo") result_array["Secret/SSH"+jindex+"sudo"] = SU_SU_AND_SUDO;
    else if ( sudo == "dzdo" ) result_array["Secret/SSH"+jindex+"sudo"] = SU_DZDO;
    else if ( sudo == "pbrun" ) result_array["Secret/SSH"+jindex+"sudo"] = SU_PBRUN;
    else if ( sudo == "Cisco 'enable'" ) CiscoEnable = TRUE;

    if (sudo) result_array["Secret/SSH"+jindex+"sudo_method"] = sudo;
    if (su_login =~ '^[A-Za-z0-9._-]+$') result_array["Secret/SSH"+jindex+"su-login"] = su_login;
    if (strlen(sudo_password) > 0 && CiscoEnable == FALSE) result_array["Secret/SSH"+jindex+"sudo-password"] = sudo_password;
    else if (strlen(sudo_password) > 0 && CiscoEnable == TRUE) result_array["Secret/SSH"+jindex+"enable-password"] = sudo_password;

    if (sudo && sudo_path && ereg(pattern:"^[A-Za-z0-9./-]+$", string:sudo_path))
    {
      if (!ereg(pattern:"/$", string:sudo_path)) sudo_path += '/';
      result_array["Secret/SSH"+jindex+"sudo_path"] = sudo_path;
    }

    result_list[j] = result_array;
    j++; # increase the index counter for the kb entry
  }

  return result_list;
}

##
# Takes the input from ssh_settings_get_settings()
# to input into the kb.
#
# @param [ssh_settings:list] list of array values to get inserted in the kb
#
###
function insert_ssh_settings_kb(ssh_settings)
{
  local_var sshi, sshk;

  foreach sshi (ssh_settings)
  {
    foreach sshk (keys(sshi))
    {
      set_kb_item(name:sshk, value:sshi[sshk]);
    }
  }
}

##
# set ssh_settings known host information
##
function ssh_settings_known_host()
{
  local_var known_hosts,lines,line,data,pref_port,port,revoked,
    ca,tmp,hostname,type,key,cert,h_s,hn,ip,e,n;

  known_hosts = script_get_preference_file_content("SSH known_hosts file : ");
  if ( ! isnull(known_hosts) )
  {
    lines = split(known_hosts, keep:FALSE);
    foreach line ( lines )
    {
      # The man page for sshd(8) says "Lines starting with `#' and empty lines are ignored as comments."
      if (line =~ "^\s*#" || line =~ "^\s*$") continue;

      data = split(line, sep:' ', keep:FALSE);
      if ( pref_port && int(pref_port) ) port = pref_port;
      else port = 22;

      revoked = FALSE;
      ca = FALSE;
      if (data[0] == '@revoked' || data[0] == '@cert-authority')
      {
        if (data[0] == '@revoked')
          revoked = TRUE;
        if (data[0] == '@cert-authority')
          ca = TRUE;

        tmp = make_list(data[1], data[2], data[3]);
        data = tmp;
      }

     # if the second field (index 1) is _not_ all numeric (i.e. is not the bits field), this line refers to an SSH2 key or certificate
     if ( data[1] !~ "^\d+$" && max_index(data) >= 3)
     {
      hostname = data[0];
      type = data[1];
      key = data[2];

      # if a certificate was provided instead of a key, retrieve the host's public key from the cert
      if ("-cert-" >< type)
      {
        cert = base64decode(str:key);
        cert = parse_ssh_cert(cert);
        key = get_public_key_from_cert(cert);
        if (isnull(key)) continue; # key will only be NULL if the public key type is unknown or unsupported

        if ("ssh-rsa" >< type)
          type = "ssh-rsa";
        if ("ssh-dss" >< type)
          type = "ssh-dss";
        key = base64encode(str:key);
      }

      if ( revoked && patterns_match_this_host(hostname, port) )
      {
        set_kb_item(name:"SSH/RevokedKey", value:key);
      }
      else if ( ca && patterns_match_this_host(hostname, port) )
      {
        set_kb_item(name:"SSH/CAKey", value:key);
      }
      else if ( hostname =~ "^\|1\|" )  # HMAC_SHA1 hash of the hostname
      {
        hostname -= "|1|";
        h_s = split(hostname, sep:'|', keep:FALSE);
        if ( base64decode(str:h_s[1]) == HMAC_SHA1(key:base64decode(str:h_s[0]), data:get_host_ip()) ||
  	   base64decode(str:h_s[1]) == HMAC_SHA1(key:base64decode(str:h_s[0]), data:'[' + get_host_ip() + ']:' + port) ||
  	   base64decode(str:h_s[1]) == HMAC_SHA1(key:base64decode(str:h_s[0]), data:'[' + get_host_name() + ']:' + port) ||
  	   base64decode(str:h_s[1]) == HMAC_SHA1(key:base64decode(str:h_s[0]), data:get_host_name() + ',' + get_host_ip()) ||
  	   base64decode(str:h_s[1]) == HMAC_SHA1(key:base64decode(str:h_s[0]), data:get_host_name()) )
  	{
          replace_kb_item(name:"SSH/KnownFingerprint/" + type, value:key);
  	}
      }
      else if ( hostname =~ "^\[.*\]:[0-9]+" )
      {
        if ( hostname == strcat("[", get_host_ip(), "]:", port)  ||
  	   hostname == strcat("[", get_host_name(), "]:", port) )
          replace_kb_item(name:"SSH/KnownFingerprint/" + type, value:key);
      }
      else if ( "," >!< hostname )
      {
       if ( hostname == get_host_ip() || hostname == get_host_name() )
  	  replace_kb_item(name:"SSH/KnownFingerprint/" + type, value:key);
      }
      else
      {
        hn = ereg_replace(pattern:"^([^,]*),.*", string:hostname, replace:"\1");
        ip = ereg_replace(pattern:"^[^,]*,(.*)", string:hostname, replace:"\1");
        if ( ip == get_host_ip() && hn == get_host_name() )
        {
  	  replace_kb_item(name:"SSH/KnownFingerprint/" + type, value:key);
        }
      }
     }
     # if fields 2-4 (indices 1-3) _are_ all numeric (the bits, exponent, and modulus fields), this line refers to an SSH1 key
     else if ( data[1] =~ "^\d+$" && data[2] =~ "^\d+$" && data[3] =~ "\d+$")
     {
      hostname = data[0];
      e = data[2];
      n = data[3];
      if ( hostname == get_host_ip() || hostname == get_host_name() )
      {
  	  replace_kb_item(name:"SSH/KnownFingerprint/ssh-rsa1", value:string(e,"|",n));
      }
     }
   }

   if ( ! get_kb_item("SSH/KnownFingerprint/ssh-rsa1") )
  	set_kb_item(name:"SSH/KnownFingerprint/ssh-rsa1", value:"QE5PVFNFVEA=");

   # this lets ssh_func.inc know that a host key was not provided for this host.
   # (It is not possible to use CAs with ssh-rsa1)
   if ( ! get_kb_item("SSH/KnownFingerprint/ssh-rsa") && ! get_kb_list("SSH/CAKey") )
  	set_kb_item(name:"SSH/KnownFingerprint/ssh-rsa", value:"QE5PVFNFVEA=");

   if ( ! get_kb_item("SSH/KnownFingerprint/ssh-dss") && ! get_kb_list("SSH/CAKey") )
  	set_kb_item(name:"SSH/KnownFingerprint/ssh-dss", value:"QE5PVFNFVEA=");
  }

}

ssh_settings = ssh_settings_get_settings();
insert_ssh_settings_kb(ssh_settings:ssh_settings);
ssh_settings_known_host();
