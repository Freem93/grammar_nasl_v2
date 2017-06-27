#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20993);
  script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2015/01/12 17:12:50 $");

  script_cve_id("CVE-2006-0812");
  script_bugtraq_id(16788);
  script_osvdb_id(23381);

  script_name(english:"Visnetic AntiVirus Plug-in for MailServer Local Privilege Escalation");
  script_summary(english:"Checks version of Visnetic AntiVirus Plug-in for MailServer");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is prone to a local privilege
escalation issue.");
 script_set_attribute(attribute:"description", value:
"The version of VisNetic AntiVirus Plug-in for MailServer installed on
the remote host does not drop its privileges before invoking other
programs. An attacker with local access can exploit this flaw to
execute arbitrary programs on the affected host with LOCAL SYSTEM
privileges.");
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2005-65/advisory/");
 script_set_attribute(attribute:"solution", value:
"Upgrade to VisNetic AntiVirus Plug-in for VisNetic MailServer version
4.6.1.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/03");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  exit(0, "cannot connect to the remote registry");
}


# Determine which version of VisNetic's AntiVirus Plug-in is installed.
key = "SOFTWARE\Deerfield.com\VisNetic AntiVirus\Plug-in\Updates";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Version");
  if (!isnull(value)) {
    ver = value[1];
    # There's a problem if it's < 4.6.1.2.
    if (ver && ver =~ "^([0-3]\.|4\.([0-5]\.|6\.(0\.|1\.[01])))") {
      security_hole(port);
    }
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# Clean up.
NetUseDel();
