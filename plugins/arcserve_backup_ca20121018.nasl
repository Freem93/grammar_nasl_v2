#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62812);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_cve_id("CVE-2012-2971", "CVE-2012-2972");
  script_bugtraq_id(56116);
  script_osvdb_id(86415, 86416);
  script_xref(name:"IAVB", value:"2012-B-0106");

  script_name(english:"CA ARCserve Backup Multiple Vulnerabilities (CA20121018) (credentialed check)");
  script_summary(english:"Checks version of CA ARCserve Backup, or ARCserve Backup Agent");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a backup application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of CA ARCserve Backup installed on the remote Windows host
is potentially affected by multiple vulnerabilities :

  - A flaw exists with how RPC requests are processed that
    could lead to code execution on server installations.
    (CVE-2012-2971)

  - A flaw exists with how RPC requests are processed that
    could cause the service to crash.  Note that this
    vulnerability affects both server and agent
    installations. (CVE-2012-2972)");

  # https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID={F9EEA31E-8089-423E-B746-41B5C9DD2AC1}
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ad7ac22");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup_client_agent_for_windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("arcserve_backup_server_installed.nasl", "arcserve_backup_agent_installed.nasl");
  script_require_keys("SMB/CA ARCserve Backup/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");

BUILD_INFO_ERR = 'Unexpected Build Info';

function display_dword (dword, nox)
{
 local_var tmp;

 if (isnull(nox) || (nox == FALSE))
   tmp = "0x";
 else
   tmp = "";

 return string (tmp,
               toupper(
                  hexstr(
                    raw_string(
                               (dword >>> 24) & 0xFF,
                               (dword >>> 16) & 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                              )
                        )
                      )
               );
}

function getbuildinfo (file)
{
  local_var fh, ret, varfileinfo, translation, stringfileinfo, data, date;
  local_var children;
  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ret = GetFileVersionEx(handle:fh);
    if (!isnull(ret)) children = ret['Children'];
    if (!isnull(children))
    {
      varfileinfo = children['VarFileInfo'];
      if (!isnull(varfileinfo))
      {
        translation =
          (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
          get_word (blob:varfileinfo['Translation'], pos:2);
        translation = toupper(display_dword(dword:translation, nox:TRUE));
      }
      stringfileinfo = children['StringFileInfo'];
      if (!isnull(stringfileinfo) && !isnull(translation))
      {
        data = stringfileinfo[translation];
        if (!isnull(data) && !isnull(data['Comments']))
        {
          if (data['Comments'] =~ '^Build [0-9\\.]+ [A-Za-z]+ [0-9/]+$')
          {
            ret = make_array();
            ret['error'] = 0;
            ret['build'] = ereg_replace(pattern:'^Build ([0-9\\.]+).*', replace:"\1", string:data['Comments']);
            date = ereg_replace(pattern:'^Build [0-9\\.]+ [A-Za-z]+ (.*)', replace:"\1", string:data['Comments']);
            date = split(date, sep:'/', keep:FALSE);
            ret['year'] = date[2];
            ret['month'] = date[0];
            ret['day'] = date[1];
          }
          else
          {
            ret['error'] = BUILD_INFO_ERR;
          }
          return ret;
        }
      }
    }
    CloseFile(handle:fh);
  }
  return NULL;
}

errors = make_list();
servversion = get_kb_item('SMB/CA ARCserve Backup Server/Version');
agentversion = get_kb_item('SMB/CA ARCserve Backup Agent/Version');

if (isnull(servversion) && isnull(agentversion)) exit(0, 'The \'SMB/CA ARCserve Backup Server/Version\' and \'SMB/CA ARCserve Backup Agent/Version\' KB items are missing.');

if (!isnull(servversion)) servpath = get_kb_item_or_exit('SMB/CA ARCserve Backup Server/Path');
if (!isnull(agentversion)) agentpath = get_kb_item_or_exit('SMB/CA ARCserve Backup Agent/Path');

# First check if we can determine the status based on the version
# of the software
info = '';
servfix = NULL;
agentfix = NULL;
if (servversion)
{
  if ((servversion =~ '^12\\.5\\.') && (ver_compare(ver:servversion, fix:'12.5.5900.32') == -1)) servfix = '12.5.5900.32 with RO49917';
  else if ((servversion =~ '^15\\.') && (ver_compare(ver:servversion, fix:'15.1.6300.24') == -1)) servfix = '15.1.6300.24 with RO49916';
  else if ((servversion =~ '^16\\.') && (ver_compare(ver:servversion, fix:'16.0.6838.1') == -1)) servfix = '16.0.6838.1 with RO49750';
}
if (agentversion)
{
  if ((agentversion =~ '^12\\.5\\.') && (ver_compare(ver:agentversion, fix:'12.5.5900.32') == -1)) agentfix = '12.5.5900.32 with RO49917';
  else if ((agentversion =~ '^15\\.') && (ver_compare(ver:agentversion, fix:'15.1.6300.24') == -1)) agentfix = '15.1.6300.24 with RO49916';
  else if ((agentversion =~ '^16\\.') && (ver_compare(ver:agentversion, fix:'16.0.6838.1') == -1)) agentfix = '16.0.6838.1 with RO49750';
}

if (servfix || agentfix)
{
  if (servfix)
  {
    info +=
      '\n  Product           : CA ARCserve Backup Server' +
      '\n  Path              : ' + servpath +
      '\n  Installed version : ' + servversion +
      '\n  Fixed version     : ' + servfix + '\n';
  }
  if (agentfix)
  {
    info +=
      '\n  Product           : CA ARCserve Backup Agent' +
      '\n  Path              : ' + agentpath +
      '\n  Installed version : ' + agentversion +
      '\n  Fixed version     : ' + agentfix + '\n';
  }
}

# If we didn't detect the Server or Agent as vulnerable, check further
extraserv = '';
extraagent = '';
if ((isnull(servfix) && !isnull(servversion)) || (isnull(agentfix) && !isnull(agentversion)))
{
  name    = kb_smb_name();
  port    = kb_smb_transport();
  #if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
  login   = kb_smb_login();
  pass    = kb_smb_password();
  domain  = kb_smb_domain();

  #soc = open_sock_tcp(port);
  #if (!soc) audit(AUDIT_SOCK_FAIL, port);
  #session_init(socket:soc, hostname:name);

  if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

  hcf_init = TRUE;
  if (isnull(servfix) && !isnull(servversion))
  {
    share = hotfix_path2share(path:servpath);
    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      audit(AUDIT_SHARE_FAIL, share);
    }

    if (servversion =~ '^12\\.5\\.')
    {
      ver = hotfix_get_fversion(path:servpath+"\as6rpc.dll");
      if (ver['error'] != HCF_OK)
        errors = make_list(errors, 'Failed to get the version of \''+servpath+'\'as6rpc.dll.');
      else
      {
        servversion = join(ver['value'], sep:'.');
        extraserv = 'as6rpc.dll';
        if (ver_compare(ver:servversion, fix:'12.5.5900.37') == -1)
        {
          info +=
            '\n  Product           : CA ARCserve Backup Server' +
            '\n  Path              : ' + servpath +
            '\n  File              : as6rpc.dll' +
            '\n  Installed version : ' + servversion +
            '\n  Fixed version     : 12.5.5900.37\n';
         }
      }
    }
    else if (servversion =~ '^15\\.')
    {
      dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\as6rpc.dll", string:servpath);
      res = getbuildinfo(file:dll);
      if (!isnull(res))
      {
        if (res['error'] == 0)
        {
          servversion += ' (' + res['month'] + '/' + res['day'] + '/' + res['year'] + ')';
          extraserv = 'as6rpc.dll';
          if (ver_compare(ver:res['build'], fix:'6300.24') == -1 ||
            (ver_compare(ver:res['build'], fix:'6300.24') == 0 && int(res['year']+res['month']+res['day']) < 20120901)
          )
          {
            info +=
              '\n  Product                  : CA ARCserve Backup Server' +
              '\n  Path                     : ' + servpath +
              '\n  File                     : as6rpc.dll' +
              '\n  Installed version (date) : ' + servversion +
              '\n  Fixed version (date)     : 15.1.6300.24 (09/01/2012) \n';
          }
        }
        else if (BUILD_INFO_ERR >< res['error']) errors = make_list('The build info from \'' + servpath + '\'as6rpc.dll contained an unexpected value.');
      }
    }
    else if (servversion =~ '^16\\.')
    {
      ver = hotfix_get_fversion(path:servpath+"\as6rpc.dll");
      if (ver['error'] != HCF_OK)
        errors = make_list(errors, 'Failed to get the version of \''+servpath+'\'as6rpc.dll');
      else
      {
        servversion = join(ver['value'], sep:'.');
        extraserv = 'as6rpc.dll';
        if (ver_compare(ver:servversion, fix:'16.0.6839.1') == -1)
        {
          info +=
            '\n  Product           : CA ARCserve Backup Agent' +
            '\n  Path              : ' + servpath +
            '\n  File              : as6rpc.dll' +
            '\n  Installed version : ' + servversion +
            '\n  Fixed version     : 16.0.6839.1\n';
        }
      }
    }
  }
  if (isnull(agentfix) && !isnull(agentversion))
  {
    if (agentversion =~ '^12\\.5\\.')
    {
      ver = hotfix_get_fversion(path:agentpath+"\as6rpc.dll");
      if (ver['error'] != HCF_OK)
        errors = make_list(errors, 'Failed to get the version of \''+servpath+'\'as6rpc.dll.');
      else
      {
        agentversion = join(ver['value'], sep:'.');
        extraagent = 'as6rpc.dll';
        if (ver_compare(ver:agentversion, fix:'12.5.5900.37') == -1)
        {
          info +=
            '\n  Product            : CA ARCserve Backup Server' +
            '\n  Path               : ' + agentpath +
            '\n  File               : as6rpc.dll' +
            '\n  Installed version : ' + agentversion +
            '\n  Fixed version      : 12.5.5900.37\n';
         }
      }
    }
    else if (agentversion =~ '^15\\.')
    {
      dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\as6rpc.dll", string:agentpath);
      res = getbuildinfo(file:dll);
      if (!isnull(res))
      {
        if (res['error'] == 0)
        {
          agentversion += ' (' + res['month'] + '/' + res['day'] + '/' + res['year'] + ')';
          extraagent = 'as6rpc.dll';
          if (ver_compare(ver:res['build'], fix:'6300.24') == -1 ||
            (ver_compare(ver:res['build'], fix:'6300.24') == 0 && int(res['year']+res['month']+res['day']) < 20120901)
          )
          {
            info +=
              '\n  Product                  : CA ARCserve Backup Server' +
              '\n  Path                     : ' + agentpath +
              '\n  File                     : as6rpc.dll' +
              '\n  Installed version (date) : ' + agentversion +
              '\n  Fixed version (date)     : 15.1.6300.24 (09/01/2012) \n';
          }
        }
        else if (BUILD_INFO_ERR >< res['error']) errors = make_list('The build info from \'' + servpath + '\'as6rpc.dll contained an unexpected value.');
      }
    }
    else if (servversion =~ '^16\\.')
    {
      ver = hotfix_get_fversion(path:agentpath+"\as6rpc.dll");
      if (ver['error'] != HCF_OK)
        errors = make_list(errors, 'Failed to get the version of \''+servpath+'\'as6rpc.dll');
      else
      {
        agentversion = join(ver['value'], sep:'.');
        extraagent = 'as6rpc.dll';
        if (ver_compare(ver:servversion, fix:'16.0.6839.1') == -1)
        {
          info +=
            '\n  Product           : CA ARCserve Backup Agent' +
            '\n  Path              : ' + agentpath +
            '\n  File              : as6rpc.dll' +
            '\n  Installed version : ' + agentversion +
            '\n  Fixed version     : 16.0.6839.1\n';
        }
      }
    }
  }
  hotfix_check_fversion_end();
}

if (info)
{
  if (report_verbosity > 0)
    security_hole(port:port, extra:info);
  else security_hole(port);

  if (max_index(errors)) exit(1, 'The results may be incomplete because of one or more errors verifying installs.');
  else exit(0);
}
else if (max_index(errors))
{
  if (max_index(errors) == 1) errmsg = errors[0];
  else errmsg = 'Errors were encountered verifying installs : \n ' + join(errors, sep:'\n ');

  exit(1, errmsg);
}
else
{
  if (servversion && agentversion)
  {
    and = ' and ';
    be = ' are ';
  }
  else
  {
    and = '';
    be = ' is ';
  }
  if (servversion)
  {
    info += 'CA ARCserve Backup Server';
    if (extraserv)
      info += ' with ' + extraserv;
    info += ' version ' + servversion;
  }
  if (agentversion)
  {
    info += and + 'CA ARCserve Backup Agent';
    if (extraagent)
      info += ' with ' + extraagent;
    info += ' version ' + agentversion;
  }

  info += be + 'installed and, therefore,' + be + 'not affected.';
  exit(0, info);
}
