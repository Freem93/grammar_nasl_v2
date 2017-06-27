#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65580);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_bugtraq_id(57904);
  script_osvdb_id(90180);
  script_xref(name:"MCAFEE-SB", value:"SB10034");

  script_name(english:"McAfee VirusScan Enterprise Local Privilege Escalation (SB10034)");
  script_summary(english:"Checks version of VSE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an antivirus application installed that is
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee VirusScan Enterprise installed on the remote
host is potentially affected by an unspecified local privilege
escalation vulnerability. By exploiting this flaw, a local attacker
could gain elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10034");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee VirusScan Enterprise 8.7 Patch 5 HF792686 or 8.8
Patch 2 HF805660.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:host_intrusion_prevention");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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
product = get_kb_item_or_exit("Antivirus/McAfee/product_name");
prodversion = get_kb_item_or_exit("Antivirus/McAfee/product_version");


if ('McAfee VirusScan Enterprise' >!< product) audit(AUDIT_INST_VER_NOT_VULN, product);
if (prodversion !~ '^8\\.(7\\.0\\.570$|8\\.0\\.(849|975)$)') audit(AUDIT_INST_VER_NOT_VULN, product, prodversion);

if (prodversion =~ '^8\\.7\\.')
{
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  key = "SOFTWARE\McAfee\VSCore\szInstallDir32";
  path = get_registry_value(handle:hklm, item:key);
  if (!isnull(path)) dll = path + "mfeapconfig.dll";
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);
}
else
{
  path = hotfix_get_commonfilesdir();
  if (!path) exit(1, "Failed to get the Common Files directory.");

  path += "\McAfee\SystemCore";
  dll = path + "\mfeapconfig.dll";
}

if (dll)
{
  ver = hotfix_get_fversion(path:dll);
  hotfix_check_fversion_end();

  if (ver['error'] == HCF_NOENT)
    audit(AUDIT_UNINST, 'McAfee VirusScan Enterprise');
  else if (ver['error'] != HCF_OK)
    audit(AUDIT_VER_FAIL, dll);
}
else audit(AUDIT_UNINST, 'McAfee VirusScan Enterprise');

version = join(ver['value'], sep:'.');
if (prodversion =~ '^8\\.7\\.')
{
  if (ver_compare(ver:version, fix:'14.4.0.506') < 0)
    fix = '14.4.0.506';
}
else
{
  if (ver_compare(ver:version, fix:'15.0.0.518') < 0)
    fix = '15.0.0.518';
}

if (fix)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Product version      : ' + prodversion +
      '\n  File                 : ' + dll +
      '\n  Current file version : ' + version +
      '\n  Fixed file version   : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, product, prodversion);
