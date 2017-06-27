#TRUSTED 4f5651e4e48c56ed92bde01bca25a5c23e94691f8abc6a05a3d4c1d0dfbe87fbf12cd3f1ba49f5d5bcc2696df12c8e368ac5be02f09fc60be1ff90a0f59d6a98193a83efe57df7cba7e2b8215d81aeab0107ce5c1ca0796f1632f47a0924257b1f780a075f4603cdfb6bdbb0f7580420098db530db44f0ea0d26245100f2aa85de816318c62a04f2169ac326e2a37cb67326f40774d7229ead3d7358c4c447e1c90e706fd41c42b17229704d1cc447e8a609b25baa80b00e5f67ae309dde5dfd00a08bf5de5126ff818dd184435940a6c5af4b2f4943ff794ac4dda355e62e8293c6f742466021cbb166d7ccf9a8e559721549fa7737af530770cf3bd30a2136de4b86fcb2dd24e302a2de660b074855d0693f6ccd450bc30a6eb70c91a9b601e1febbe40617cbc70ddab6df558360dc16374b6481e9c2c953a251c7b616c2fd88a32fe5193615d9cfcb85744780185d8cd88cbbae06b774addd40133f09efcb56e6717d6854984ac124c6630a6f90e1330df252cdd147985d5e6db3469feab90f6c97438d124dcbeb54abf77f35f4417fada3deb88b95dbbd531fc5c2aaf14d59d4ad7a1d347a7f3d88c5d4f44ca188d581bced04a3090d57978fb918f98ab12b69452bf5ddf2b2c564e3e64f7fea5c7576f1cf2e0502d28ce9fa59ac962b35c662b7487d08ce6c4a002c693a0cf06959284fcb2aa00039600b74ce550063ef
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10394);
  script_version("1.147");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/01/19");

  script_name(english:"Microsoft Windows SMB Log In Possible");
  script_summary(english:"Attempts to log into the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to log into the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a Microsoft Windows operating system or
Samba, a CIFS/SMB server for Unix. It was possible to log into it
using one of the following accounts :

- NULL session
- Guest account
- Supplied credentials");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/143474");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/246261");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2000-2017 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("global_settings.nasl", "netbios_name_get.nasl", "cifs445.nasl", "logins.nasl", "smb_nativelanman.nasl");
  if ( NASL_LEVEL >= 2202 ) script_dependencies("kerberos.nasl");
  script_require_keys("SMB/name", "SMB/transport");
  script_require_ports(139, 445, "/tmp/settings");
  exit(0);
}

include("smb_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

# Plugin is run by the local Windows Nessus Agent
if (get_kb_item("nessus/product/agent"))
{
  # Note: some Windows credentialed plugins call:
  # script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
  # Here we manually set the KBs
  set_kb_item(name:"SMB/login", value:"");
  set_kb_item(name:"SMB/password", value:"");

  # Set Local checks KB items
  set_kb_item(name:"Host/windows_local_checks", value:TRUE);
  set_kb_item(name:"Host/local_checks_enabled", value:TRUE);

  # set domain/workgroup if known
  # set_kb_item(name:"SMB/domain", value:"");
  exit(0);
}

global_var session_is_admin, port;

##
# kdc will only be present for credentials where the user has
# specified kerberos authentication on scanners >= nessus 6.0
##
function login(lg, pw, dom, lm, ntlm, kdc)
{
  local_var r, r2, soc;

  session_is_admin = 0;

  if (kdc)
  {
    replace_kb_item(name:"Kerberos/SMB/kdc_use_tcp", value:kdc["use_tcp"]);
    replace_kb_item(name:"SMB/only_use_kerberos", value:TRUE);
    replace_kb_item(name:"KerberosAuth/enabled", value:TRUE);
    # used by open_sock_ex() (nessus >= 6)
    replace_kb_item(name:"Secret/SMB/kdc_hostname", value:kdc["host"]);
    replace_kb_item(name:"Secret/SMB/kdc_port", value:int(kdc["port"]));
    # used by open_sock_kdc() (nessus < 6)
    replace_kb_item(name:"Secret/kdc_hostname", value:kdc["host"]);
    replace_kb_item(name:"Secret/kdc_port", value:int(kdc["port"]));
    replace_kb_item(name:"Secret/kdc_use_tcp", value:int(kdc["use_tcp"]));
  }
  # Use latest version of SMB that Nessus and host share (likely SMB 2.002)
  if (!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
  r = NetUseAdd(login:lg, password:pw, domain:dom, lm_hash:lm, ntlm_hash:ntlm, share:"IPC$");
  if (r == 1)
  {
    NetUseDel(close:FALSE);
    r2 = NetUseAdd(share:"ADMIN$");
    if (r2 == 1) session_is_admin = TRUE;
  }
  NetUseDel();

  # If that fails, fallback to SMB1
  if (r != 1)
  {
    if (!smb_session_init(smb2:FALSE)) audit(AUDIT_FN_FAIL, 'smb_session_init');
    r = NetUseAdd(login:lg, password:pw, domain:dom, lm_hash:lm, ntlm_hash:ntlm, share:"IPC$");
    if (r == 1)
    {
      NetUseDel(close:FALSE);
      r2 = NetUseAdd(share:"ADMIN$");
      if (r2 == 1) session_is_admin = TRUE;
    }
    NetUseDel();
  }

  if (kdc)
  {
    # this needs to be deleted after each authentication attempt to avoid having stale KDC data in the KB
    # (e.g. 1st credentials attempt kerberos auth, 2nd credentials do not attempt kerberos auth).
    # if kerberos auth succeeds, this data will be saved in the KB permanently below where SMB/login et al are saved
    rm_kb_item(name:"Kerberos/SMB/kdc_use_tcp");
    rm_kb_item(name:"SMB/only_use_kerberos");
    rm_kb_item(name:"KerberosAuth/enabled");
    rm_kb_item(name:"Secret/SMB/kdc_hostname");
    rm_kb_item(name:"Secret/SMB/kdc_post");
    rm_kb_item(name:"Secret/kdc_hostname");
    rm_kb_item(name:"Secret/kdc_port");
    rm_kb_item(name:"Secret/kdc_use_tcp");
  }

  if (r == 1)
  {
    if (session_is_admin) replace_kb_item(name:"SMB/use_smb2", value:session_is_smb2());
    return TRUE;
  }
  else
  {
    return FALSE;
  }
}

login_has_been_supplied = 0;
port = kb_smb_transport();
name = kb_smb_name();

# the port scanner ran and determined the SMB transport port isn't open
if (get_kb_item("Host/scanned") && !get_port_state(port))
{
  audit(AUDIT_PORT_CLOSED, port);
}

soc = open_sock_tcp(port);
if (!soc)
{
  audit(AUDIT_SOCK_FAIL, port);
}
close(soc);

##
# Get all of the required parameters from the kb and
# set them to an array for access.
##
for (i = 0; TRUE; i ++)
{
  l = get_kb_item("SMB/login_filled/" + i );
  if (l)
  {
    l = ereg_replace(pattern:"([^ ]*) *$", string:l, replace:"\1");
  }

  p = get_kb_item("SMB/password_filled/" + i );
  if (p)
  {
    p = ereg_replace(pattern:"([^ ]*) *$", string:p, replace:"\1");
  }
  else
  {
    p = "";
  }

  d = get_kb_item("SMB/domain_filled/" + i );
  if (d)
  {
    d = ereg_replace(pattern:"([^ ]*) *$", string:d, replace:"\1");
  }

  t = get_kb_item("SMB/password_type_filled/" + i );

  if (!get_kb_item("Kerberos/global"))
  {
    kdc_host = get_kb_item("SMB/kdc_hostname_filled/" + i );
    kdc_port = get_kb_item("SMB/kdc_port_filled/" + i );
    kdc_use_tcp = get_kb_item("SMB/kdc_use_tcp_filled/" + i );
  }

  if (l)
  {
    login_has_been_supplied ++;
    logins[i] = l;
    passwords[i] = p;
    domains[i] = d;
    password_types[i] = t;
    if (kdc_host && kdc_port)
    {
      kdc_info[i] = make_array(
        "host", kdc_host,
        "port", int(kdc_port),
        "use_tcp", kdc_use_tcp
      );
    }
  }
  else break;
}

smb_domain = string(get_kb_item("SMB/workgroup"));

if (smb_domain)
{
  smb_domain = ereg_replace(pattern:"([^ ]*) *$", string:smb_domain, replace:"\1");
}

##
# Start testing access levels for SMB service
##
hole = 0;
rand_lg = rand_str(length:8, charset:"abcdefghijklmnopqrstuvwxyz");
rand_pw = rand_str(length:8);

# Test Null sessions
if (login(lg:NULL, pw:NULL, dom:NULL))
  null_session = TRUE;
else
  null_session = FALSE;

# Test administrator Null Login
if (!supplied_logins_only)
{
  if (login(lg:"administrator", pw:NULL, dom:NULL) && !session_is_guest())
  {
    admin_no_pw = TRUE;
  }
  else
  {
    admin_no_pw = FALSE;
  }

  # Test open to anyone login settings
  if (login(lg:rand_lg, pw:rand_pw, dom:NULL))
  {
    any_login = TRUE;
    set_kb_item(name:"SMB/any_login", value:TRUE);
  }
  else
  {
    any_login = FALSE;
  }
}

##
# Start testing supplied creds
##
supplied_login_is_correct = FALSE;
working_login = NULL;
working_password = NULL;
working_password_type = NULL;
working_kdc = NULL;
working_domain = NULL;

valid_logins = make_list();
valid_passwords = make_list();
for (i = 0; logins[i] && !supplied_login_is_correct; i++)
{
  logged_in = 0;
  user_login = logins[i];
  k_password = user_password = passwords[i];
  user_domain = domains[i];
  p_type = password_types[i];
  kdc = kdc_info[i];

  if (p_type == 0)
  {
    lm = ntlm = NULL;
  }
  if (p_type == 1)
  {
    lm = hex2raw2(s:tolower(user_password));
    ntlm = user_password = NULL;
  }
  else if (p_type == 2)
  {
    ntlm = hex2raw2(s:tolower(user_password));
    lm = user_password = NULL;
  }

  if (login(lg:user_login, pw:user_password, dom:user_domain, lm:lm, ntlm:ntlm, kdc:kdc) && !session_is_guest())
  {
    logged_in ++;
    if (session_is_admin) supplied_login_is_correct = TRUE;
    if (!working_login || session_is_admin)
    {
      working_login = user_login;
      if (isnull(user_password))
      {
        if (!isnull(lm)) user_password = hexstr(lm);
        else if (!isnull(ntlm)) user_password = hexstr(ntlm);
      }

      working_password = user_password;
      working_password_type = p_type;
      working_kdc = kdc;
      working_domain = user_domain;
    }
  }
  else
  {
    if (tolower(user_domain) != tolower(smb_domain))
    {
      if (login(lg:user_login, pw:user_password, dom:smb_domain, lm:lm, ntlm:ntlm, kdc:kdc) && !session_is_guest())
      {
        logged_in ++;
        if (session_is_admin) supplied_login_is_correct = TRUE;
        if (!working_login || session_is_admin)
        {
          working_login = user_login;
          if (isnull(user_password))
          {
            if (!isnull(lm)) user_password = hexstr(lm);
            else if (!isnull(ntlm)) user_password = hexstr(ntlm);
          }
          working_password = user_password;
          working_password_type = p_type;
          working_domain = smb_domain;
        }
      }
    }

    if (!logged_in)
    {
      if (login(lg:user_login, pw:user_password, dom:NULL, lm:lm, ntlm:ntlm, kdc:kdc) && !session_is_guest())
      {
        if (session_is_admin) supplied_login_is_correct = TRUE;
        if (!working_login || session_is_admin)
        {
          working_login = user_login;
          if (isnull(user_password))
          {
            if (!isnull(lm)) user_password = hexstr(lm);
            else if (!isnull(ntlm)) user_password = hexstr(ntlm);
          }
          working_password = user_password;
          working_password_type = p_type;
          working_domain = NULL;
        }
        smb_domain = NULL;
      }
    }
  }
}

if (working_login)
{
  supplied_login_is_correct = TRUE;
  user_login = working_login;
  user_password = working_password;
  user_password_type = working_password_type;
  user_kdc = working_kdc;
  smb_domain = working_domain;
}

report = '';

if (null_session || supplied_login_is_correct || admin_no_pw || any_login)
{
  if ( null_session != 0 )
  {
    set_kb_item(name:"SMB/null_session_enabled", value:TRUE);
    report += '- NULL sessions are enabled on the remote host.\n';
  }

  if (supplied_login_is_correct)
  {
    if (!user_password) user_password = "";

    set_kb_item(name:"SMB/login", value:user_login);
    set_kb_item(name:"SMB/password", value:user_password);
    set_kb_item(name:"SMB/password_type", value:user_password_type);
    if (!isnull(user_kdc))
    {
      replace_kb_item(name:"Secret/SMB/kdc_hostname",  value:user_kdc["host"]);
      replace_kb_item(name:"Secret/SMB/kdc_port",      value:int(user_kdc["port"]));
      replace_kb_item(name:"Secret/kdc_hostname",      value:kdc["host"]);
      replace_kb_item(name:"Secret/kdc_port",          value:int(kdc["port"]));
      replace_kb_item(name:"Secret/kdc_use_tcp",       value:int(kdc["use_tcp"]));
      replace_kb_item(name:"Kerberos/SMB/kdc_use_tcp", value:user_kdc["use_tcp"]);
      replace_kb_item(name:"KerberosAuth/enabled",     value:TRUE);
      replace_kb_item(name:"SMB/only_use_kerberos",    value:TRUE);
    }
    if (smb_domain != NULL)
    {
      set_kb_item(name:"SMB/domain", value:smb_domain);
      report += '- The SMB tests will be done as ' + smb_domain + '\\' + user_login + '/******\n';
    }
    else
    report += '- The SMB tests will be done as ' + user_login + '/******\n';
  }

  # https://discussions.nessus.org/message/9562#9562 -- Apple's Time Capsule accepts any login with a
  # blank password
  if (admin_no_pw && !any_login && !login(lg:rand_str(length:8), pw:""))
  {
    set_kb_item(name:"SMB/blank_admin_password", value:TRUE);
    report += '- The \'administrator\' account has no password set.\n';
    hole = 1;
    if (!supplied_login_is_correct)
    {
      set_kb_item(name:"SMB/login", value:"administrator");
      set_kb_item(name:"SMB/password", value:"");
      set_kb_item(name:"SMB/domain", value:"");
    }
  }

  if (any_login)
  {
    set_kb_item(name:"SMB/guest_enabled", value:TRUE);
    report += '- Remote users are authenticated as \'Guest\'.\n';
    if (!supplied_login_is_correct && !admin_no_pw)
    {
      set_kb_item(name:"SMB/login", value:rand_lg);
      set_kb_item(name:"SMB/password", value:rand_pw);
      set_kb_item(name:"SMB/domain", value:"");
    }
  }

  if (null_session)
  {
    if (!supplied_login_is_correct && !admin_no_pw && !any_login)
    {
      set_kb_item(name:"SMB/login", value:"");
      set_kb_item(name:"SMB/password", value:"");
      set_kb_item(name:"SMB/domain", value:"");
    }
  }

  if (!supplied_login_is_correct && !admin_no_pw && login_has_been_supplied)
    set_kb_item(name:"HostLevelChecks/smb/failed", value:TRUE);

  if (supplied_login_is_correct || admin_no_pw)
  {
    if (!get_kb_item("SMB/not_windows"))
    {
      set_kb_item(name:"Host/windows_local_checks", value:TRUE);
      set_kb_item(name:"Host/local_checks_enabled", value:TRUE);
    }

    kb_dom = get_kb_item("SMB/domain");
    kb_lg  = get_kb_item("SMB/login");
    if (isnull(kb_dom)) kb_dom = get_host_ip();
    login_used = strcat(kb_dom, '\\', kb_lg);

    set_kb_item(name:"HostLevelChecks/smb_login", value:login_used);

    if (defined_func("report_xml_tag"))
    {
      report_xml_tag(tag:"local-checks-proto", value:"smb");
      report_xml_tag(tag:"smb-login-used",     value:login_used);
    }
  }
  security_note(port:port, extra:report);
}
else
{
  if (isnull(get_kb_item('SMB/login_filled/0'))) audit(AUDIT_MISSING_CREDENTIALS, "Windows");
  else exit(0, "Failed to connect to the SMB service. Could not authenticate with the supplied credentials.");
}
