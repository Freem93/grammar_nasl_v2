#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15822);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2015/01/12 17:12:47 $");

 script_cve_id("CVE-2002-1059");
 script_bugtraq_id(5287);
 script_osvdb_id(4991);

 script_name(english:"SecureCRT SSH-1 Protocol Version String Remote Overflow");
 script_summary(english:"Determines the version of SecureCRT");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a buffer
overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is using a vulnerable version of SecureCRT, a
SSH/Telnet client built for Microsoft Windows operating systems.

It has been reported that SecureCRT contains a remote buffer overflow
allowing an SSH server to execute arbitrary commands via an especially
long SSH1 protocol version string.");
 script_set_attribute(attribute:"solution", value:"Upgrade to SecureCRT 3.2.2, 3.3.4, 3.4.6, 4.1 or newer");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SecureCRT SSH1 Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/23");
script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/24");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("audit.inc");

# Connect to the appropriate share.
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
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

key = "SOFTWARE\VanDyke\SecureCRT\License";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 key = "SOFTWARE/VanDyke/SecureCRT/Evaluation License/Version";
 if ( isnull(key_h) )
 {
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
 }
}

version = RegQueryValue(handle:key_h, item:"Version");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel();
if ( !isnull(version) )
{
 set_kb_item(name:"SMB/SecureCRT/Version", value:version[1]);
 if (egrep(pattern:"^(2\.|3\.([01]|2[^.]|2\.1[^0-9]|3[^.]|3\.[1-3][^0-9]|4[^.]|4\.[1-5][^0-9])|4\.0 beta [12]([^0-9]|$))", string:version[1]))
  security_hole(kb_smb_transport());
}

