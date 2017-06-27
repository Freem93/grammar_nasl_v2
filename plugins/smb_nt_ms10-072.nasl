#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49949);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2010-3243", "CVE-2010-3324");
  script_bugtraq_id(42467, 43703);
  script_osvdb_id(68123, 68548);
  script_xref(name:"MSFT", value:"MS10-072");

  script_name(english:"MS10-072: Vulnerabilities in SafeHTML Could Allow Information Disclosure (2412048)");
  script_summary(english:"Checks SharePoint / Groove / Office Web Apps version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple cross-site scripting
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The versions of SharePoint Services, SharePoint Server, Groove, or
Office Web Apps installed on the remote host have multiple cross-site
scripting vulnerabilities.

A remote attacker could exploit them by tricking a user into making a
malicious request, resulting in arbitrary script code execution.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Aug/178");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-072");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SharePoint Services 3.0,
SharePoint Foundation 2010, SharePoint Server 2007, Groove Server
2010, and Office Web Apps.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "groove_server_installed.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS10-072';
kbs = make_list("2345212", "2345304", "2345322", "2346298", "2346411");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


get_kb_item_or_exit("SMB/WindowsVersion");


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
sharepoint_path = NULL;
owa_path = NULL;

key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\12.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
 value = RegQueryValue(handle:key_h, item:"Location");
 if (!isnull(value))
   sharepoint_path = value[1];

 RegCloseKey(handle:key_h);
}

# Check SharePoint 2010 if 2007 wasn't detected
if (isnull(sharepoint_path))
{
  key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Location");
    if (!isnull(value))
      sharepoint_path = value[1];

    RegCloseKey(handle:key_h);
  }
}

# Check Office Web Apps
key = "SOFTWARE\Microsoft\Office Server\14.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
 value = RegQueryValue(handle:key_h, item:"InstallPath");
 if (!isnull(value))
   owa_path = value[1];

 RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel (close:FALSE);

sharepointserver_exe = NULL;

kb = '';
if (sharepoint_path)
{
  sharepointserver_exe = sharepoint_path + '\\Microsoft.Office.Server.Conversions.Launcher.exe';
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:sharepoint_path);
  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\BIN\Mssph.dll", string:sharepoint_path);

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
  # Determine if this is Sharepoint Server or Sharepoint Services
  handle = CreateFile (file:sharepointserver_exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
  if ( ! isnull(handle) )
  {
    kb = '2345212';
    CloseFile(handle:handle);
  }
  else kb = '2345304';
}
NetUseDel();

report = "";

if (!isnull(sharepoint_ver))
{
  # Versions < 12.0.6544.5000
  v = sharepoint_ver;
  if (
    v[0] == 12 && v[1] == 0 && (v[2] < 6544 || (v[2] == 6544 && v[3] < 5000))
  )
  {
    info =
      '\n  Product           : SharePoint Server 2007 / SharePoint Services 3.0\n'+
      '  Path              : ' + sharepoint_path + "\bin\mssph.dll"+ '\n' +
      '  Installed version : ' + join(v, sep:'.') + '\n' +
      '  Fixed version     : 12.0.6544.5000\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }

  # Versions <  14.0.5123.5000
  if (v[0] == 14 && v[1] == 0 && (v[2] < 5123 || (v[2] == 5123 && v[3] < 5000)))
  {
    info =
      '\n  Product           : SharePoint Foundation 2010\n'+
      '  Path              : ' + sharepoint_path + "\bin\mssph.dll"+ '\n' +
      '  Installed version : ' + join(v, sep:'.') + '\n' +
      '  Fixed version     : 14.0.5123.5000\n';
    hotfix_add_report(info, bulletin:bulletin, kb:'2345322');
    vuln = TRUE;
  }
}

if (owa_path)
{
  share = owa_path[0] + '$';
  if (is_accessible_share(share:share))
  {
    owa_path = owa_path + "\WebServices\ConversionService\Bin\Converter";
    old_report = hotfix_get_report();

    if (hotfix_is_vulnerable(file:"msoserver.dll", version:"14.0.5120.5000", min_version:"14.0.0.0", path:owa_path))
    {
      file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:owa_path, replace:"\1\msoserver.dll");
      kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
      version = get_kb_item(kb_name);

      info =
       '\n  Product           : Office Web Apps 2010' +
       '\n  Path              : ' + owa_path + '\\msoserver.dll' +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 14.0.5120.5000' + '\n';

      hcf_report = '';
      hotfix_add_report(old_report + info, bulletin:bulletin, kb:'2346411');
      vuln = TRUE;
    }
  }
  else debug_print('is_accessible_share() failed on ' + owa_path);
}

# Groove Server
paths = get_kb_list("SMB/groove_server/path");
if (paths)
{
  # I think there can be one Groove Server install at most, but we'll
  # assume there can be multiple to be on the safe side
  foreach path (make_list(paths))
  {
    share = path[0] + '$';
    if (!is_accessible_share(share:share))
    {
      debug_print('is_accessible_share() failed on ' + path);
      continue;
    }

    old_report = hotfix_get_report();

    if (hotfix_is_vulnerable(file:"Groovems.dll", version:"14.0.5123.5000", min_version:"14.0.0.0", path:path))
    {
      file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\Groovems.dll");
      kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
      version = get_kb_item(kb_name);

      info =
       '\n  Product           : Groove Server 2010' +
       '\n  Path              : ' + path + '\\Groovems.dll' +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 14.0.5123.5000' + '\n';

      hcf_report = '';
      hotfix_add_report(old_report + info, bulletin:bulletin, kb:'2346298');
      vuln = TRUE;
    }
  }

}

hotfix_check_fversion_end();

if (vuln)
{
  set_kb_item(name:'SMB/Missing/MS10-072', value:TRUE);
  set_kb_item(name: 'www/0/XSS', value: TRUE);
  hotfix_security_warning();
}
else exit(0, 'The host is not affected');
