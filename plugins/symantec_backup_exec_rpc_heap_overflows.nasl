#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22226);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2006-4128");
  script_bugtraq_id(19479);
  script_osvdb_id(27909);

  script_name(english:"Symantec Backup Exec Multiple Heap Overflow RCE (SYM06-014)");
  script_summary(english:"Checks for version of Symantec Backup Exec.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Windows remote host contains Symantec Backup Exec for Windows
Server or Backup Exec Continuous Protection Server, a commercial
backup product. The version of the software installed on the remote
host is affected by multiple heap overflow conditions involving
specially crafted calls to its RPC interfaces. An authenticated,
remote attacker can exploit these issues to crash the affected
application or execute arbitrary code with elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2006.08.11.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:veritas_backup_exec");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
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
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
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


# Get paths where the affected files are installed.
paths = NULL;
npaths = 0;
#
# - Backup Exec CPS
key = "SOFTWARE\VERITAS\Backup Exec CPS";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"ENLSharedPath");
  if (!isnull(value)) paths[npaths++] = value[1];

  RegCloseKey(handle:key_h);
}
# - Backup Exec
key = "SOFTWARE\VERITAS\Backup Exec\Install";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[0]; ++i) {
    value = RegEnumValue(handle:key_h, index:i);
    if (!isnull(value))
    {
      subkey = value[1];
      if (strlen(subkey) && subkey =~ "^Path [0-9]")
      {
        # Get the install path.
        value = RegQueryValue(handle:key_h, item:subkey);
        if (!isnull(value)) paths[npaths++] = value[1];
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();
if (!npaths) exit(0);


# Check the version.
for (i=0; i<=npaths; i++)
{
  path = paths[i];
  share = ereg_replace(pattern:"(^[A-Za-z]):.*", replace:"\1$", string:path);
  if (is_accessible_share(share:share))
  {
    if (
      hotfix_check_fversion(file:"beremote.exe", path:path, version:"10.1.5629.34", min_version:"10.1.5629.0") == HCF_OLDER ||
      hotfix_check_fversion(file:"beremote.exe", path:path, version:"10.0.5520.32", min_version:"10.0.5520.0") == HCF_OLDER ||
      hotfix_check_fversion(file:"beremote.exe", path:path, version:"10.0.5484.36", min_version:"10.0.5484.0") == HCF_OLDER ||
      hotfix_check_fversion(file:"beremote.exe", path:path, version:"9.1.4691.58", min_version:"9.1.4691.0") == HCF_OLDER ||
      hotfix_check_fversion(file:"rxservice.exe", path:path, version:"10.1.327.901", min_version:"10.1.325.0") == HCF_OLDER
    )
    {
      security_warning(port);
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
}
audit(AUDIT_HOST_NOT, 'affected');
