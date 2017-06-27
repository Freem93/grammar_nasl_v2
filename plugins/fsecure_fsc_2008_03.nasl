#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35088);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/08 20:42:13 $");

  script_cve_id("CVE-2008-6085");
  script_bugtraq_id(31846);
  script_osvdb_id(49189);
  script_xref(name:"Secunia", value:"32352");

  script_name(english:"F-Secure RPM Parsing Integer Overflow RCE (FSC-2008-3)");
  script_summary(english:"Checks version of fm4av.dll.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application installed on the remote host is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of F-Secure Anti-Virus installed on the remote host is
affected by an integer overflow condition. Provided F-Secure is
configured to scan inside compressed archives, an attacker can exploit
this issue, via a specially crafted RPM file, to execute arbitrary
code.

Note that, in a typical configuration, on-access scanning does not
scan inside compressed archives.");
  # https://web.archive.org/web/20081024083648/http://www.f-secure.com/security/fsc-2008-3.shtml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c8a0c6e");
  script_set_attribute(attribute:"solution", value:
"Apply the vendor-supplied patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f-secure:f-secure_anti-virus");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("Settings/ParanoidReport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");
#     Since we are not certain if 'Scan inside compressed files' setting
#     is enabled, we run the check only if report_paranoia is set.

if (report_paranoia < 2) audit(AUDIT_PARANOID);


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

path = NULL;
fix =  NULL;

hkey = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(hkey))
{
  value = RegQueryValue(handle:hkey, item:item);
  if (!isnull(value))
    path = value[1];
    fix  = "1.9.14341.18630";
  RegCloseKey (handle:hkey);
}

# See if gatekeeper is installed.

if(isnull(path))
{
 key = "SOFTWARE\Data Fellows\F-Secure\Content Scanner Server";
 item = "Path";

 hkey = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 if (!isnull(hkey))
 {
  value = RegQueryValue(handle:hkey, item:item);
  if (!isnull(value))
  {
    path = value[1];
    fix =  "2.0.14340.7363";
  }
  RegCloseKey (handle:hkey);
 }
}

RegCloseKey (handle:hklm);
NetUseDel ();

if(isnull(path)) exit(0);

if (!isnull(path) && !isnull(fix) && is_accessible_share())
 {
  # fm4av.dll is updated after applying the patch.
  if ( hotfix_check_fversion(file:"fm4av.dll", version:fix, path:path) == HCF_OLDER )
     security_hole(port);
  hotfix_check_fversion_end();
 }
else audit(AUDIT_HOST_NOT, 'affected');

