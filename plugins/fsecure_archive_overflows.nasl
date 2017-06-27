#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20804);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/08 20:42:13 $");

  script_cve_id("CVE-2006-0337", "CVE-2006-0338");
  script_bugtraq_id(16309);
  script_osvdb_id(22632, 22633);

  script_name(english:"F-Secure ZIP/RAR Archive Handling Overflow Multiple RCE");
  script_summary(english:"Checks for ZIP/RAR archive handling overflow vulnerabilities in F-Secure products.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application installed on the remote host is affected by
multiple remote code execution vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of F-Secure Anti-Virus installed on the remote Windows
host is affected by multiple flaws in the way it handles ZIP and RAR
archives. An attacker can exploit these, via specially crafted files,
to bypass scanning or execute arbitrary code with SYSTEM privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zoller.lu/");
  # https://web.archive.org/web/20060308134525/http://www.f-secure.com/security/fsc-2006-1.shtml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3072c99e");
  script_set_attribute(attribute:"solution", value:
"Enable auto-updates if using F-Secure Internet Security 2004-2006,
F-Secure Anti-Virus 2004-2006, or F-Secure Personal Express version
6.20 or earlier. Alternatively, apply the appropriate hotfix as
referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f-secure:f-secure_anti-virus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

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

key[0] = "SOFTWARE\Data Fellows\F-Secure\Anti-Virus";
key[1] = "SOFTWARE\Data Fellows\F-Secure\Content Scanner Server";

item = "Path";

for (i=0; i<max_index(key); i++)
{
 hkey = RegOpenKey(handle:hklm, key:key[i], mode:MAXIMUM_ALLOWED);
 if (!isnull(hkey))
 {
  value = RegQueryValue(handle:hkey, item:item);
  if (!isnull(value))
    path[i] = value[1];

  RegCloseKey (handle:hkey);
 }
 else
   path[i] = NULL;
}

RegCloseKey (handle:hklm);
NetUseDel ();


vulnerable = FALSE;

for (i=0; i<max_index(path); i++)
{
 if (!isnull(path[i]) && is_accessible_share())
 {
  if ( hotfix_check_fversion(file:"fm4av.dll", version:"1.6.34.90", path:path[i]) == HCF_OLDER )
    vulnerable = TRUE;
  else if ( hotfix_check_fversion(file:"fslfpi.dll", version:"2.3.8.0", path:path[i]) == HCF_OLDER )
    vulnerable = TRUE;

  hotfix_check_fversion_end();
  if (vulnerable == TRUE)
    break;
 }
}

if (vulnerable == TRUE)
  security_hole(port);
else audit(AUDIT_HOST_NOT, 'affected');
