#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72186);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_bugtraq_id(58163);
  script_osvdb_id(90611);
  script_xref(name:"MCAFEE-SB", value:"SB10038");

  script_name(english:"McAfee VirusScan Enterprise 8.8 Patch 2 < HF778101 Local Privilege Escalation (SB10038)");
  script_summary(english:"Checks the file version of mfeapconfig.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an antivirus application that is affected
by a local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee VirusScan Enterprise installed on the remote
Windows host is 8.8 Patch 2 prior to Hotfix 778101. It is, therefore,
affected by a privilege escalation vulnerability due to an unspecified
error related to the enforcement of security permissions. A local
attacker can exploit this to gain elevated privileges. Note that this
issue only affects installations where McAfee Access Protection has
been turned off.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10038");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=KB76727");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee VirusScan Enterprise version 8.8 Patch 2 HF778101
or Patch 3.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "mcafee_installed.nasl");
  script_require_keys("Antivirus/McAfee/installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("Antivirus/McAfee/installed");
product_name = get_kb_item_or_exit("Antivirus/McAfee/product_name");
version = get_kb_item_or_exit("Antivirus/McAfee/product_version");

if ("McAfee VirusScan Enterprise" >!< product_name) audit(AUDIT_INST_VER_NOT_VULN, product_name);

if (ver_compare(ver:version, fix:'8.8.0.975', strict:FALSE) != 0)
{
  audit(AUDIT_INST_VER_NOT_VULN, product_name, version);
}

vuln = FALSE;

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\McAfee\SystemCore\szInstallDir32";
path = get_registry_value(handle:hklm, item:key);

if (isnull(path))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, product_name);
}

arch = get_kb_item("SMB/ARCH");
if (isnull(arch)) arch = "x86"; # default to x86

# Is Access Protection enabled?
access_protection_enabled = get_registry_value(
  handle: hklm,
  item  : "SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\BehaviourBlocking\APEnabled"
);

# If x64 try another key
if (isnull(access_protection_enabled) && arch == "x64")
  access_protection_enabled = get_registry_value(
    handle: hklm,
    item  : "SOFTWARE\Wow6432Node\McAfee\SystemCore\VSCore\On Access Scanner\BehaviourBlocking\APEnabled"
  );
RegCloseKey(handle:hklm);

if (isnull(access_protection_enabled))
{
  close_registry();
  audit(AUDIT_FN_FAIL, 'get_registry_value', "NULL when accessing registry value 'APEnabled'");
}

close_registry(close:FALSE);

# Now check the version of the executable.
dll = path + "\mfeapconfig.dll";
dll_ver = hotfix_get_fversion(path:dll);
hotfix_check_fversion_end();

if (dll_ver['error'] != HCF_OK)
{
  if (dll_ver['error'] == HCF_NOAUTH) exit(1, "Unable to access " + product_name + " file: " + dll);
  else if (dll_ver['error'] == HCF_NOENT) audit(AUDIT_UNINST, product_name);
  else if (dll_ver['error'] == HCF_NOVER) audit(AUDIT_VER_FAIL, dll);
  else exit(1, "Unknown error when attempting to access " + dll + ".");
}

dll_ver = join(dll_ver['value'], sep:'.');

dll_fix = '15.0.0.537';

if (ver_compare(ver:dll_ver, fix:dll_fix, strict:FALSE) == -1)
  vuln = TRUE;

if (report_paranoia < 2 && access_protection_enabled)
  vuln = FALSE;

if (vuln)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Product version      : ' + version +
      '\n  File                 : ' + dll +
      '\n  Current file version : ' + dll_ver +
      '\n  Fixed file version   : ' + dll_fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, product_name, version);
