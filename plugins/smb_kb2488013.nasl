#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51587);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_cve_id("CVE-2010-3971");
  script_bugtraq_id(45246);
  script_osvdb_id(69796);
  script_xref(name:"CERT", value:"634956");
  script_xref(name:"EDB-ID", value:"15708");
  script_xref(name:"EDB-ID", value:"15746");
  script_xref(name:"Secunia", value:"42510");

  script_name(english:"MS KB2488013: Internet Explorer CSS Import Rule Processing Arbitrary Code Execution");
  script_summary(english:"Checks if couple of workarounds referenced in KB 2488013 have been applied.");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through a web
browser.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing one of the workarounds referenced in KB
2488013.

The remote version of IE reportedly fails to correctly process certain
specially crafted Cascading Style Sheets (CSS), which could result in
arbitrary code execution on the remote system.");

  script_set_attribute(attribute:"solution", value:"Apply Microsoft suggested workarounds.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS11-003 Microsoft Internet Explorer CSS Recursive Import Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Dec/110");
  script_set_attribute(attribute:"see_also", value:"http://www.breakingpointsystems.com/community/blog/ie-vulnerability/");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2488013/en-us");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2488013");

script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "microsoft_emet_installed.nasl", "smb_nt_ms10-090.nasl", "smb_nt_ms11-003.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/Missing/MS11-003");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/Missing/MS11-003");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
arch = get_kb_item("SMB/ARCH");

version = get_kb_item("SMB/IE/Version");
v = split(version, sep:".", keep:FALSE);
if (int(v[0]) < 6 || int(v[0]) > 8)
 exit(0, "IE version "+ version + " is not known to be affected.");

if (hotfix_check_sp(xp:4, win2003:3, vista:3, win7:1) <= 0)
  exit(0, 'The host is not affected based on its version / service pack.');
if (hotfix_check_server_core() == 1)
  exit(0, "Windows Server Core installs are not affected.");

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}
# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}
# Find where it's installed.
path = NULL;
sdb_found      = FALSE;
emet_installed = FALSE;
emet_with_ie   = FALSE;

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\{e4874249-daf0-48c2-a614-f2a51a0a4e01}";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"DatabasePath");
  if (!isnull(value)) path = value[1];
  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);

# 'Fix it' solution on x64 does not register the path in registry.
if (isnull(path) && !isnull(arch) && arch == "x64")
{
  systemroot = hotfix_get_systemroot();
  path = systemroot + "\AppPatch\Custom\{e4874249-daf0-48c2-a614-f2a51a0a4e01}.sdb";
}

if (!isnull(path))
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  sdb =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:path);

  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to "+share+" share.");
  }

  fh = CreateFile(
    file:sdb,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    sdb_found = TRUE;
    CloseFile(handle:fh);
  }
}
NetUseDel();

# Check if EMET is installed

if (!isnull(get_kb_item("SMB/Microsoft/EMET/Installed")))
  emet_installed = TRUE;

# Check if EMET is configured with IE.
# The workaround does not specifically ask to enable DEP
# but if IE is configured with EMET, dep is enabled by default.

emet_list = get_kb_list("SMB/Microsoft/EMET/*");
if(!isnull(emet_list))
{
  foreach entry (keys(emet_list))
  {
    if("iexplore.exe" >< entry && "/dep" >< entry)
    {
      dep = get_kb_item(entry);
      if(!isnull(dep) && dep == 1)
        emet_with_ie = TRUE;
    }
  }
}

if (sdb_found && isnull(get_kb_item("SMB/Missing/MS10-090")))
  exit(0, "'Fix it' solution referenced in KB 2488013 has been applied.");

if (emet_with_ie) exit(0,"Internet Explorer is configured with EMET.");

info = '';

# If both workarounds are not applied, report...
if (!sdb_found && !emet_with_ie)
{
  if (!sdb_found)
   info = '\n' +
     ' - \'Fix it\' solution referenced in KB 2488013 is not applied.\n';

  if (!emet_installed)
    info += ' - Microsoft Enhanced Mitigation Experience Toolkit (EMET) is not installed.\n';
  else
    info += ' - Microsoft Enhanced Mitigation Experience Toolkit (EMET) is installed,\n'+
      'however Internet Explorer is not configured with EMET.\n';
}
# If 'Fix it' solution was applied, but MS10-090 is missing, report...
else if (!emet_with_ie && sdb_found && !isnull(get_kb_item("SMB/Missing/MS10-090")))
{
  info = '\n'+
    ' - \'Fix it\' solution referenced in KB 2488013 has been being applied, however\n'+
    'Microsoft Security Patch (MS10-090) has not been applied.\n';
}

if (info)
{
  report = '\n' +
    'Nessus determined the workaround was not applied based on the following \n'+
    'information : \n'+
    info ;

  if (report_verbosity > 0) security_hole(port:port,extra:report);
  else security_hole(port);
}
