#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18616);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_cve_id("CVE-2005-2144", "CVE-2005-2145");
  script_bugtraq_id(14123);
  script_osvdb_id(17682, 17683);
  script_name(english:"Prevx Pro 2005 <= 1.0.0.1 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in Prevx Pro 2005 <= 1.0.0.1");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple issues.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Prevx Pro 2005, an intrusion protection
system for Windows.

The installed version of Prevx Pro 2005 reportedly suffers from
multiple vulnerabilities that allow local attackers to bypass the
application's security features.");
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/alerts/2005/Jun/1014346.html");
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/05");

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


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");

port = kb_smb_transport();
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


# Get the software's version.
key = "SOFTWARE\PREVX\Prevx Pro";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"DisplayName");
  if (!isnull(value)) name = value[1];
  else name = NULL;

  value = RegQueryValue(handle:key_h, item:"BuildVersion");
  if (!isnull(value)) ver = value[1];

  RegCloseKey(handle:key_h);
}
else name = NULL;


# Check the version of Prevx Pro 2005 installed.
#
# nb: 16777217 <=> 0x1000001
if (
  !isnull(name) && !isnull(ver) &&
  "Prevx Pro 2005" >< name &&
  int(ver) <= 16777217
) security_hole(port);


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
