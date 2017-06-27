#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31467);
  script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2008-1310", "CVE-2008-1311", "CVE-2008-1312");
  script_bugtraq_id(28078, 28079, 28187);
  script_osvdb_id(42932, 43060, 43061);
  script_xref(name:"Secunia", value:"29207");

  script_name(english:"PacketTrap pt360 TFTP Server < 1.0.3302.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PacketTrap pt360 Tool suite");

 script_set_attribute(attribute:"synopsis", value:"The remote TFTP server is affected by multiple flaws.");
 script_set_attribute(attribute:"description", value:
"PacketTrap pt360 Tool Suite is installed on the remote system. It is a
single reporting solution that integrates various free network
management tools provided by PacketTrap Networks.

The tool suite includes a TFTP server component that is susceptible to
a directory traversal and a denial of service attack. By sending a
specially crafted string, an attacker may be able to crash the
affected service or to read or write arbitrary files on the remote
system, subject to the privileges of the user under which the TFTP
server runs.

If it is run by a user with Administrator privileges, successful
exploitation of the issue may lead to a complete system compromise.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Mar/17");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Mar/22" );
 script_set_attribute(attribute:"see_also", value:"http://www.emediawire.com/releases/2008/2/prweb731563.htm" );
 script_set_attribute(attribute:"solution", value:"Upgrade to PacketTrap pt360 Tool Suite version 1.0.3302.0 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 22);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/13");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");

# Figure out where the installer recorded information about it.
key = NULL;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);

foreach name (keys(list))
{
  prod = list[name];
  if (prod && "PacketTrap pt360 Tool Suite" >< prod)
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}
if (isnull(key)) exit(0);

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Find out where it was installed.
path = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}

# Determine the version of PacketTrapToolkit.exe
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\PacketTrapToolkit.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  fix = split("1.0.3302.0", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        report = string(
          "\n",
          "PacketTrap pt360 Tool Suite ", version, " is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
