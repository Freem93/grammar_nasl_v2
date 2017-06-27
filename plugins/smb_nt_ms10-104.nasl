#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51176);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2010-3964");
  script_bugtraq_id(45264);
  script_osvdb_id(69817);
  script_xref(name:"EDB-ID", value:"20122");
  script_xref(name:"MSFT", value:"MS10-104");

  script_name(english:"MS10-104: Vulnerability in Microsoft SharePoint Could Allow Remote Code Execution (2455005)");
  script_summary(english:"Checks SharePoint version");

  script_set_attribute(attribute:"synopsis", value:"The remote host has a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of SharePoint Server 2007 running on the remote host has a
remote code execution vulnerability. The Document Conversions Launcher
Service does not properly validate SOAP requests before processing
them.

A remote attacker could exploit this by submitting a specially crafted
SOAP request, resulting in arbitrary code execution in the security
context of a guest account.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-104");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for SharePoint Server 2007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS10-104 Microsoft Office SharePoint Server 2007 Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:0);
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

path = NULL;

# Determine where it's installed.

key = "SOFTWARE\Microsoft\Office Server\12.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
 value = RegQueryValue(handle:key_h, item:"BinPath");
 if (!isnull(value))
   path = value[1];

 RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel (close:FALSE);

if (!path)
{
 NetUseDel();
 exit(1, 'Unable to get SharePoint Server path');
}

# this file should be included with SharePoint Server 2007, but not
# SharePoint Services (which is not affected)
path += "\Microsoft.Office.Server.Conversions.Launcher.exe";



get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-104';
kbs = make_list("2433089");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:path);

r = NetUseAdd(share:share);
if ( r != 1 )
{
 NetUseDel();
 audit(AUDIT_SHARE_FAIL, share);
}

handle = CreateFile (file:dll, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);


kb = "2433089";
if ( ! isnull(handle) )
{
  v = GetFileVersion(handle:handle);
  CloseFile(handle:handle);
  if ( ! isnull(v) )
  {
    fix = '12.0.6547.5000';
    if (v[0] == 12 && ver_compare(ver:v, fix:fix) == -1)
    {
      info =
        '\n  Product           : Sharepoint Server 2007' +
        '\n  Path              : ' + path +
        '\n  Installed version : ' + join(v, sep:'.') +
        '\n  Fix               : ' + fix + '\n';
      set_kb_item(name:"SMB/Missing/MS10-104", value:TRUE);
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      hotfix_security_hole();
      exit(0);
      # never reached
   }
  }
}

NetUseDel();

exit(0, 'The host is not affected.');
