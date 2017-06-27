#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19703);
  script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_cve_id("CVE-2005-2957");
  script_bugtraq_id(14824);
  script_osvdb_id(19384);

  script_name(english:"Avira Desktop for Windows ACE Archive Handling Buffer Overflow");
  script_summary(english:"Checks for ACE archive handling buffer overflow vulnerability in Avira Desktop for Windows");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
buffer overflow.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Avira Desktop for Windows.

The installed version of Avira Desktop for Windows is reportedly prone
to a stack-based buffer overflow when scanning ACE archives with long
filenames. An attacker can exploit this issue to execute arbitrary
code on the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2005-43/advisory/");
 script_set_attribute(attribute:"solution", value:"Upgrade AVPACK32.DLL to version 6.31.1.7 or later via online update.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/14");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);
name = kb_smb_name();
port = kb_smb_transport();
#if (!get_port_state(port)) exit(0);
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();


# Connect to the remote registry.
#soc = open_sock_tcp(port);
#if (!soc) exit(0);
#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(1);
}


# Get the software's installation directory from the registry.
key = "SOFTWARE\AVIRA GmbH\AVIRA Desktop";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
dir = NULL;
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"AVWPath");
  if (!isnull(value)) dir = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);


# If it's installed...
if (dir) {
  # Read version / build info directly from the affected DLL.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:dir);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    NetUseDel();
    exit(1);
  }

  file = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\AVPack32.dll", string:dir);
  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);

    # There's a problem if it's earlier than version 6.31.1.7.
    if (!isnull(ver)) {
      if (
        (ver[0] < 6) ||
        (ver[0] == 6 && ver[1] < 31) ||
        (ver[0] == 6 && ver[1] == 31 && ver[2] < 1) ||
        (ver[0] == 6 && ver[1] == 31 && ver[2] == 1 && ver[3] < 7)
      ) security_hole(port);
    }
  }
}


# Clean up.
NetUseDel();
