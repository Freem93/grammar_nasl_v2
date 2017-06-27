#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(38718);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:42:13 $");

  script_cve_id("CVE-2009-1782");
  script_bugtraq_id(34849);
  script_osvdb_id(54685, 54686);
  script_xref(name:"Secunia", value:"35008");

  script_name(english:"F-Secure Products ZIP/RAR File Scan Evasion (FSC-2009-1)");
  script_summary(english:"Checks version of fm4av.dll.");

 script_set_attribute(attribute:"synopsis", value:
"An antivirus application installed on the remote host is affected by
a scan evasion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has an antivirus product from F-Secure installed. The
installed version of the product fails to accurately scan certain ZIP
and RAR archive files. Therefore, it may be possible for such files to
evade detection from the scanning engine.");
  # https://web.archive.org/web/20090510034628/http://www.f-secure.com/en_EMEA/support/security-advisory/fsc-2009-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cf449be");
  script_set_attribute(attribute:"solution", value:
"Apply the vendor-supplied patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f-secure:f-secure_anti-virus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
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

key = "SOFTWARE\Data Fellows\F-Secure\Content Scanner Server";
item = "Path";

hkey = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(hkey))
{
  value = RegQueryValue(handle:hkey, item:item);
  if (!isnull(value))
    path = value[1];

  RegCloseKey (handle:hkey);
}

RegCloseKey (handle:hklm);
NetUseDel ();

if(isnull(path))
  exit(0);

if (!isnull(path) && is_accessible_share())
{
  # fm4av.dll is updated after applying the patch.
  if ( hotfix_check_fversion(file:"fm4av.dll", version:"3.1.15160.1", path:path) == HCF_OLDER )
     security_warning(port);
  hotfix_check_fversion_end();
}
else audit(AUDIT_HOST_NOT, 'affected');
