#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(21644);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:42:13 $");

  script_cve_id("CVE-2006-2838");
  script_bugtraq_id(18201);
  script_osvdb_id(25937);

  script_name(english:"F-Secure Multiple Products Web Console Pre-authentication Overflow RCE");
  script_summary(english:"Checks version of F-Secure Web Console.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application installed on the remote host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of F-Secure Internet Gatekeeper and/or F-Secure Anti-Virus
for Microsoft Exchange installed on the remote host is affected by a
buffer overflow condition in its web console. An unauthenticated,
remote attacker can exploit this to cause a denial of service
condition or the execution of arbitrary code.

Note that the web console by default accepts connections only from the
local host; therefore, this issue can be exploited remotely only if
the web console has been specifically configured to accept connections
remotely.");
 # https://web.archive.org/web/20060629212230/http://www.f-secure.com/security/fsc-2006-3.shtml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2afb73dd");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix as described in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f-secure:f-secure_anti-virus");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:f-secure:internet_gatekeeper");
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

# Connect to the appropriate share.
get_kb_item_or_exit("SMB/Registry/Enumerated");
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
if (rc != 1) exit(0);


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Determine which F-Secure products are installed.
key = "SOFTWARE\Data Fellows\F-Secure";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i) {
    prod = RegEnumKey(handle:key_h, index:i);
    if (strlen(prod)) prods[prod]++;
  }
  RegCloseKey(handle:key_h);
}


# Determine the path to Web Console if an affected product is installed.
if (
  prods["Web User Interface"] &&
  (
    prods["Anti-Virus Agent for Microsoft Exchange"] ||
    prods["Anti-Virus for Internet Gateways"]
  )
)
{
  key = "SOFTWARE\Data Fellows\F-Secure\Web User Interface";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  path = NULL;
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Path");
    if (!isnull(value)) path = value[1];

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
NetUseDel();
if (isnull(path)) exit(0);


# Check the version.
share = ereg_replace(pattern:"(^[A-Za-z]):.*", replace:"\1$", string:path);
if (is_accessible_share(share:share))
{
  path += "bin";

  fixed = NULL;
  if (prods["Anti-Virus for Internet Gateways"]) fixed = "1.3.37.0";
  else if (prods["Anti-Virus Agent for Microsoft Exchange"]) fixed = "1.2.144.0";

  if (
    fixed &&
    hotfix_check_fversion(file:"fswebuid.exe", version:fixed, path:path) == HCF_OLDER
  )
  {
     security_hole(port);
     hotfix_check_fversion_end();
     exit(0);
  }
  else
  {
    hotfix_check_fversion_end();
    audit(AUDIT_HOST_NOT, 'affected');
  }
}
else audit(AUDIT_SHARE_FAIL, share);
