#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57945);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2012-0017", "CVE-2012-0144", "CVE-2012-0145");
  script_bugtraq_id(51928, 51934, 51937);
  script_osvdb_id(79262, 79263, 79264);
  script_xref(name:"MSFT", value:"MS12-011");
  script_xref(name:"IAVB", value:"2012-B-0017");

  script_name(english:"MS12-011 : Vulnerabilities in Microsoft SharePoint Could Allow Elevation of Privilege (2663841)");
  script_summary(english:"Checks SharePoint version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple privilege escalation and
information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of SharePoint Foundation or SharePoint Server installed on
the remote host has multiple privilege escalation and information
disclosure vulnerabilities.

A remote attacker could exploit them by tricking a user into making a
malicious request, resulting in arbitrary script code execution.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-011");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SharePoint Server 2010 and
SharePoint Foundation 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");



get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS12-011';
kbs = make_list('2597124', '2553413');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/WindowsVersion");

global_var hklm;

function get_key(attr, key)
{
  local_var item, key_h, value;

  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (isnull(key_h))
    return NULL;

  item = RegQueryValue(handle:key_h, item:attr);
  if (!isnull(item))
    value = item[1];

  RegCloseKey(handle:key_h);

  return value;
}

function get_ver(base, file)
{
  local_var handle, path, r, share, ver;

  if (isnull(base))
    return NULL;

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:base);
  path = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\" + file, string:base);
  ver = NULL;

  r = NetUseAdd(share:share);
  if (r != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  handle = CreateFile(
    file               : path,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );
  if (!isnull(handle))
  {
    ver = GetFileVersion(handle:handle);
    CloseFile(handle:handle);
  }

  NetUseDel(close:FALSE);

  return ver;
}

# Get credentials and connection information.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

# Connect to IPC share.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Get path information for SharePoint Foundation.
spsvc_path = get_key(
  key  : 'SOFTWARE\\Microsoft\\Shared Tools\\Web Server Extensions\\14.0',
  attr : "Location"
);

# Get path information for SharePoint Server 2010.
sps_2010_path = get_key(
  key  : 'SOFTWARE\\Microsoft\\Office Server\\14.0',
  attr : "InstallPath"
);

# Get path information for SharePoint Server 2010 OSRV and WOSRV.
osrv_path = get_key(
  key  : 'SOFTWARE\\Microsoft\\Shared Tools\\Web Server Extensions\\14.0',
  attr : "Location"
);

# Get path information for SharePoint Server 2010 DLC.
dlc_path = osrv_path;

# Close connection to registry.
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# Get version information for SharePoint Services and Foundation.
spsvc_file = 'ISAPI\\Owssvr.dll';
spsvc_ver = get_ver(base:spsvc_path, file:spsvc_file);

# Get version information for SharePoint Server 2010.
sps_2010_file = 'Bin\\Microsoft.sharepoint.publishing.dll';
sps_2010_ver = get_ver(base:sps_2010_path, file:sps_2010_file);

# Get version for SharePoint Server 2010 OSRV and WOSRV.
osrv_file = 'ISAPI\\Microsoft.Office.Server.dll';
osrv_ver = get_ver(base:osrv_path, file:osrv_file);

# Get version for SharePoint Server 2010 DLC.
dlc_file = 'ISAPI\\Microsoft.office.policy.dll';
dlc_ver = get_ver(base:dlc_path, file:dlc_file);

# Close connection to server.
NetUseDel();

######################################################################
# Microsoft SharePoint Foundation 2010
# ------------------------------------
# [KB2494001] Owssvr.dll (14.0.6114.5001)
######################################################################
if (!isnull(spsvc_ver))
{
  fix = NULL;
  name = "Microsoft SharePoint Foundation 2010";
  fix = "14.0.6114.5001";
  kb = "2553413";

  spsvc_ver = join(spsvc_ver, sep:".");
  if (!isnull(fix) && ver_compare(ver:spsvc_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + spsvc_path + spsvc_file +
      '\n  Installed version : ' + spsvc_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}
######################################################################
# Microsoft Office SharePoint Server 2010
# ---------------------------------------
# [KB2494022] Microsoft.sharepoint.publishing.dll (14.0.6113.5000)
######################################################################
if (!isnull(sps_2010_ver))
{
  name = "SharePoint Server 2010";
  fix = "14.0.6113.5000";
  kb = "2597124";

  sps_2010_ver = join(sps_2010_ver, sep:".");
  if (ver_compare(ver:sps_2010_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + sps_2010_path + sps_2010_file +
      '\n  Installed version : ' + sps_2010_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

######################################################################
# Microsoft SharePoint Server 2010
# --------------------------------
# [KB2560885]  OSRV: Microsoft.office.server.dll (14.0.6114.5000)
######################################################################
if (!isnull(osrv_ver))
{
  name = "SharePoint Server 2010 OSRV";
  fix = "14.0.6114.5000";
  kb = "2497124";

  osrv_ver = join(osrv_ver, sep:".");
  if (ver_compare(ver:osrv_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + osrv_path + osrv_file +
      '\n  Installed version : ' + osrv_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

######################################################################
# Microsoft SharePoint Server 2010 Document Lifecycle Components
# --------------------------------------------------------------
# [KB2566954] Microsoft.office.policy.dll (14.0.6114.5000)
######################################################################
if (!isnull(dlc_ver))
{
  name = "SharePoint Server 2010 Document Lifecycle Components";
  fix = "14.0.6114.5000";
  kb = "2597124";

  dlc_ver = join(dlc_ver, sep:".");
  if (ver_compare(ver:dlc_ver, fix:fix) < 0)
  {
    info =
      '\n  Product           : ' + name +
      '\n  Path              : ' + dlc_path + dlc_file +
      '\n  Installed version : ' + dlc_ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

if (vuln)
{
  # Flag the system as vulnerable.
  set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
  set_kb_item(name:"www/0/XSS", value:TRUE);

  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected.");
}
