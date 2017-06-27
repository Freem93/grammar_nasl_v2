#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18355);
  script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_cve_id("CVE-2005-1675", "CVE-2005-1676", "CVE-2005-1677", "CVE-2005-1678");
  script_bugtraq_id(13682, 13684, 13685, 13686, 13688);
  script_osvdb_id(16693, 16694, 16695, 16696, 16697);
  script_xref(name:"CERT", value:"155610");
  script_xref(name:"CERT", value:"232232");
  script_xref(name:"CERT", value:"372618");
  script_xref(name:"CERT", value:"443370");
  script_xref(name:"CERT", value:"514386");
  script_name(english:"Groove Virtual Office / Workspace Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in Groove Virtual Office / Workspace");

 script_set_attribute(attribute:"synopsis", value:"The remote Windows application is affected by multiple issues.");
 script_set_attribute(attribute:"description", value:
"According the remote registry, the version of Groove Virtual Office or
Groove Workspace on the remote host suffers from multiple
vulnerabilities. Some of these flaws may allow for arbitrary script
execution, disclosure of sensitive information, and denial of service,
all from remote users.");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Workspace v2.5n build 1871 or Virtual Office v3.1a build
2364 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/20");

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


# Look in the registry for the version of Groove installed.
name = kb_smb_name();
port = kb_smb_transport();
#if (!get_port_state(port)) exit(1);
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();


# Connect to the remote registry.
#soc = open_sock_tcp(port);
#if (!soc) exit(1);
#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(1);
}


# Determine the version and build number of Groove.
#
# nb: the version number in the registry doesn't seem to use
#     alphabetic characters; eg, "3.1" rather than "3.1a".
key = "SOFTWARE\Groove Networks, Inc.\Groove";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"CurVer");
  if (!isnull(value)) ver = value[1];

  value = RegQueryValue(handle:key_h, item:"BuildNumber");
  if (!isnull(value)) build = int(value[1]);

  RegCloseKey(handle:key_h);

  # Check whether it's vulnerable.
  if (!isnull(ver) && !isnull(build)) {
    iver = split(ver, sep:'.', keep:FALSE);

    if (
      ( int(iver[0]) < 2 || ( int(iver[0]) == 2 && int(iver[1]) < 5 ) ) ||
      (  ver == "2.5" && build < 1871 ) ||
      (  ver == "3.0" ) ||
      (  ver == "3.1" && build < 2364 )
     ) security_hole(port);
  }
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
