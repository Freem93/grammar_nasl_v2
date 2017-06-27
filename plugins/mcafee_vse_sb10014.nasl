#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72204);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2010-5143");
  script_osvdb_id(84882);
  script_xref(name:"MCAFEE-SB", value:"SB10014");

  script_name(english:"McAfee VirusScan Enterprise < 8.8 / 8.7 HF643440 CLI Local Privilege Escalation (SB10014)");
  script_summary(english:"Checks version of McAfee VSE.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an antivirus application that is affected
by a CLI local privilege escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has a version of McAfee VirusScan Enterprise
(VSE) prior to 8.8 or 8.7 Hot-Fix 643440.  It is, therefore, reportedly
affected by a CLI local privilege escalation vulnerability that could
disable VSE and its connection to McAfee ePolicy Orchestrator (ePO)."
  );
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10014");
  script_set_attribute(attribute:"solution", value:"Upgrade to VSE 8.8 (or later) or apply 8.7 Hot-Fix 643440.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/29");

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

# If version 8.8 or greater is detected, then it is not vulnerable.
if (ver_compare(ver:version, fix:'8.8', strict:FALSE) >= 0)
{
  audit(AUDIT_INST_VER_NOT_VULN, product_name, version);
}

# If version earlier than 8.7 is detected, then report as
# vulnerable.
if (ver_compare(ver:version, fix:'8.7', strict:FALSE) == -1)
{
  fixed_version = '8.8';
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version + '\n';

    security_note(port:port, extra:report);
    exit(0);
  }
  else security_note(port);
  exit(0);
}


# If we reach this far, then we're looking at version 8.7 and
# have to check if the hotfix is applied.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\McAfee\VSCore\szInstallDir32";
path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, product_name);
}

close_registry(close:FALSE);

# Now check the version of the executable.
dll = path + "Mcvssnmp.dll";
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

dll_fix = '14.1.0.587';

if (ver_compare(ver:dll_ver, fix:dll_fix, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Product version      : ' + version +
      '\n  File                 : ' + dll +
      '\n  Current file version : ' + dll_ver +
      '\n  Fixed file version   : ' + dll_fix + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, product_name, version);
