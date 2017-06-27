#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22312);
  script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2006-3985", "CVE-2008-4420");
  script_bugtraq_id(19143);
  script_osvdb_id(27490, 27492, 53478);
  script_xref(name:"Secunia", value:"21180");

  script_name(english:"DynaZip < 5.0.0.8 / 6.0.0.5 Zip Archive Handling Multiple Overflows");
  script_summary(english:"Checks version of DynaZip's dzip32.dll / dzips32.dll");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a library that is affected by several
buffer overflow vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The version of the DynaZip Max or DynaZip Max Secure installed on the
remote host contains a DLL that reportedly is prone to stack-based
overflows when repairing or updating a specially crafted ZIP file.
Successful exploitation allows an attacker to execute arbitrary code
on the affected host subject to the user's privileges.

Note that DynaZip libraries are included in some third-party
applications to provide support for handling ZIP files.");
 script_set_attribute(attribute:"see_also", value:"http://vuln.sg/dynazip5007-en.html");
 script_set_attribute(attribute:"see_also", value:"http://vuln.sg/turbozip6-en.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/441083/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/441084" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Jul/582" );
 # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01622011
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be445f03" );
 script_set_attribute(attribute:"solution", value:
"Either upgrade to DynaZip Max 5.0.0.8 / DynaZip Max Secure 6.0.0.5 or
later or contact the appropriate vendor for a fix.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/07");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("audit.inc");
include("misc_func.inc");

# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(0);


#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0, "cannot connect to the remote registry");
}


# Determine possible paths for the DLLs.
npaths = 0;
paths = make_array();
# - Windows system directories (DynaZip Max uses the SYSTEM32 directory)
sys_root = hotfix_get_systemroot();
if (sys_root)
{
  paths[npaths++] = sys_root + "\system";
  paths[npaths++] = sys_root + "\system32";
}
# - PowerArchiver
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\POWERARC.EXE";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item)) {
    path = item[1];
    path =  ereg_replace(pattern:'^(.+)\\\\POWERARC\\.EXE$', replace:"\1", string:path);
    paths[npaths++] = path;
  }
  RegCloseKey(handle:key_h);
}
# - TurboZIP
key = "SOFTWARE\FileStream.com\TurboZIP";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  item = RegQueryValue(handle:key_h, item:"Install Path");
  if (!isnull(item)) {
    path = item[1];
    paths[npaths++] = path;
  }
  RegCloseKey(handle:key_h);
}
key = "SOFTWARE\FileStream\TurboZIP Express";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item)) {
    path = item[1];
    paths[npaths++] = path;
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (!npaths)
{
  NetUseDel();
  exit(0);
}
NetUseDel();


# Check each path until we find an affected version.
vulnerable = 0;
for (i=0; i<npaths; i++)
{
  path = paths[i];
  share = ereg_replace(pattern:"(^[A-Za-z]):.*", replace:"\1$", string:path);

  if (
    is_accessible_share(share:share) &&
    (
      hotfix_check_fversion(file:"dzip32.dll",  path:path, version:"5.0.0.8") == HCF_OLDER ||
      hotfix_check_fversion(file:"dzips32.dll", path:path, version:"6.0.0.5") == HCF_OLDER
    )
  )
  {
    vulnerable = 1;
    break;
  }
}
hotfix_check_fversion_end();


if (vulnerable) hotfix_security_hole();
