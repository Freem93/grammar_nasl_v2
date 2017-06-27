#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(31682);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:42:13 $");

  script_cve_id("CVE-2008-1412");
  script_bugtraq_id(28282);
  script_osvdb_id(43222);

  script_name(english:"F-Secure Archive Handling RCE (FSC-2008-2)");
  script_summary(english:"Checks for archive handling vulnerabilities in F-Secure products.");

  script_set_attribute(attribute:"synopsis", value:
"A antivirus application installed on the remote host is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of F-Secure Anti-Virus installed on the remote host fails
to handle specially crafted archives. A remote attacker can exploit
this issue to crash the application or execute arbitrary code with
SYSTEM privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.ee.oulu.fi/research/ouspg/protos/testing/c10/archive/");
  # https://web.archive.org/web/20080320060446/http://www.f-secure.com/security/fsc-2008-2.shtml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3da6d1ba");
  script_set_attribute(attribute:"solution", value:
"Enable auto-updates if using F-Secure Internet Security 2006-08.
Alternatively, apply the appropriate hotfix as referenced in the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f-secure:f-secure_anti-virus");
  script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");

name    = kb_smb_name();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();

#if (!get_port_state(port))
#  exit(0);

#soc = open_sock_tcp(port);
#if (!soc) exit(0);

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  exit(0);
}

path = NULL;

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
 NetUseDel();
 exit (0);
}

key = "SOFTWARE\Data Fellows\F-Secure\Anti-Virus";
item = "Path";

hkey = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if (!isnull(hkey))
 {
  value = RegQueryValue(handle:hkey, item:item);
  if (!isnull(value))
    path = value[1];
  RegCloseKey (handle:hkey);
 }
 else
   path = NULL;

RegCloseKey (handle:hklm);
NetUseDel ();

if(isnull(path)) exit(0);

vulnerable = FALSE;
if (!isnull(path) && is_accessible_share())
 {
  # Couple of dll files get updated after applying the patch.
  if ( hotfix_check_fversion(file:"fm4av.dll", version:"1.9.14082.6716", path:path) == HCF_OLDER )
    vulnerable = TRUE;
  else if ( hotfix_check_fversion(file:"fslfpi.dll", version:"2.4.4.0", path:path) == HCF_OLDER )
    vulnerable = TRUE;
  hotfix_check_fversion_end();
 }

if (vulnerable == TRUE)
  security_hole(port);
else audit(AUDIT_HOST_NOT, 'affected');
