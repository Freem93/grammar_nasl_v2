#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46846);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2010-0817", "CVE-2010-1257", "CVE-2010-1264");
  script_bugtraq_id(39776, 40409, 40559);
  script_osvdb_id(64170, 65211, 65220);
  script_xref(name:"MSFT", value:"MS10-039");
  script_xref(name:"IAVA", value:"2010-A-0079");

  script_name(english:"MS10-039: Vulnerabilities in Microsoft SharePoint Could Allow Elevation of Privilege (2028554)");
  script_summary(english:"Checks SharePoint / InfoPath version");

  script_set_attribute(attribute:"synopsis", value:"The remote host has multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of InfoPath, SharePoint
Server, or SharePoint Services with the following vulnerabilities :

  - A cross-site scripting vulnerability in Help.aspx.
    (CVE-2010-0817)

  - An information disclosure vulnerability in the
    toStaticHTML() API. (CVE-2010-1257)

  - A denial of service vulnerability, triggered by sending
    specially crafted requests to the help page.
    (CVE-2010-1264)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-039");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for InfoPath 2003, InfoPath
2007, SharePoint Server 2007, and SharePoint Services 3.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:infopath");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_services");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-039';
kbs = make_list("979441", "979445", "980923", "983444");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


# First get the version of SharePoint
if (!get_kb_item("SMB/Registry/Enumerated"))
  exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

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

# Determine where it's installed.
path = NULL;

key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\12.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
 value = RegQueryValue(handle:key_h, item:"Location");
 if (!isnull(value))
   path = value[1];

 RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel (close:FALSE);


kb = '';
sharepointserver_exe = NULL;
if (path)
{
  sharepointserver_exe = path + '\\Microsoft.Office.Server.Conversions.Launcher.exe';
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\BIN\Mssph.dll", string:path);

  r = NetUseAdd(share:share);
  if ( r != 1 )
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  handle = CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
  if ( ! isnull(handle) )
  {
    sharepoint_ver = GetFileVersion(handle:handle);
    CloseFile(handle:handle);
  }
  handle = CreateFile (file:sharepointserver_exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
  if ( ! isnull(handle) )
  {
    kb = '979445';
    CloseFile(handle:handle);
  }
  else kb = '983444';
}
NetUseDel();

report = "";
vuln = FALSE;

# The bulletin says:
#
#   For supported editions of Microsoft Office SharePoint Server 2007, in
#   addition to security update package KB979445, customers also need to install
#   the security update for Microsoft Windows SharePoint Services 3.0 (KB982331)
#   to be protected from the vulnerabilities described in this bulletin.
#
# KB982331 addresses MS10-038, and is unrelated to SharePoint Services 3.0 -
# it's for Excel.  I'm going to assume that part of the sentence is
# erroneous, and they mean KB983444.  The SharePoint Server and SharePoint
# Services KBs both update mssph.dll, and the SharePoint Services KB updates
# it to a later version, so it looks like checking for that one file/version
# will cover everything SharePoint-related in this bulletin
#
if (!isnull(sharepoint_ver))
{
  # Version 12.0.6529.5000
  v = sharepoint_ver;
  if (v[0] == 12 && v[1] == 0 && (v[2] < 6529 || (v[2] == 6529 && v[3] < 5000)))
  {
    report +=
      '\nProduct         : SharePoint Server 2007 / SharePoint Services 3.0\n'+
      'Path              : ' + path + "\bin\mssph.dll"+ '\n' +
      'Installed version : ' + join(v, sep:'.') + '\n' +
      'Fix               : 12.0.6529.5000\n';
    hotfix_add_report(report, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

# Check InfoPath 2003 & 2007
report = "";
installs = get_kb_list("SMB/Office/InfoPath/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    infopath_ver = install - 'SMB/Office/InfoPath/' - '/ProductPath';
    path = installs[install];

    v = split(infopath_ver, sep:'.', keep:FALSE);
    for (i = 0; i < max_index(v); i++)
      v[i] = int(v[i]);

    if (
      (v[0] == 11 && v[1] == 0 && v[2] < 8233) ||
      (v[0] == 12 && v[1] == 0 && (v[2] < 6529 || (v[2] == 6529 && v[3] < 5000)))
    )
    {
      if (v[0] == 11)
      {
        edition = '2003';
        fix = '11.0.8233.0';
        kb = '980923';
      }
      else
      {
        edition = '2007';
        fix = '12.0.6529.5000';
        kb = '979441';
      }
      report =
        '\nProduct          : Microsoft Office InfoPath '+edition+'\n'+
        'Path              : '+path+'\n'+
        'Installed version : '+infopath_ver+'\n' +
        'Fix               : '+fix+'\n';
      hotfix_add_report(report, bulletin:bulletin, kb:kb);
    }
  }
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/MS10-039', value:TRUE);
  set_kb_item(name: 'www/0/XSS', value: TRUE);

  hotfix_security_warning();
}
else audit(AUDIT_HOST_NOT, 'affected');
