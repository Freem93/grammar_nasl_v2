#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69098);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"Adobe PageMaker Detection");
  script_summary(english:"Detects installs of Adobe PageMaker.");

  script_set_attribute(attribute:"synopsis", value:"The remote host has page layout software installed.");
  script_set_attribute(attribute:"description", value:
"The remote host has Adobe PageMaker installed.  Adobe PageMaker is page
layout software that was discontinued and succeeded by Adobe
InDesign.");
  script_set_attribute(attribute:"see_also", value:"https://www.adobe.com/products/pagemaker/");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:pagemaker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app = "Adobe PageMaker";

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Adobe\PageMaker70\AdobeDirectory";

path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

close_registry(close:FALSE);

path -= "\RSRC";
exe = path + "\Pm70.exe";
ver = hotfix_get_fversion(path:exe);

if (ver["error"] != HCF_OK)
{
  NetUseDel();
  if (ver["error"] == HCF_NOENT)
     audit(AUDIT_UNINST, app);
  exit(1, "Error obtaining the version of '" + exe + "'.");
}

hotfix_check_fversion_end();

version = join(ver["value"], sep:".");

kb_base = "SMB/Adobe_PageMaker/";
set_kb_item(name:kb_base + "Installed", value:TRUE);
set_kb_item(name:kb_base + "Version", value:version);
set_kb_item(name:kb_base + "Path", value:path);

register_install(
  app_name:app,
  path:path,
  version:version,
  cpe:"cpe:/a:adobe:pagemaker");

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version +
    '\n';
}

security_note(port:get_kb_item("SMB/transport"),  extra:report);
