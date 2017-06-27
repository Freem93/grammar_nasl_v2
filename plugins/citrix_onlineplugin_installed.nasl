#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62308);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/12 02:12:32 $");

  script_name(english:"Citrix Online Plug-in Installed");
  script_summary(english:"Checks for Citrix Online Plug-in / ICA Client");

  script_set_attribute(attribute:"synopsis", value:"A remote access application is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Citrix Online-plugin, formerly ICA Client, a client application for
accessing remote documents and virtual desktops, is installed on the
remote Windows host.");
  # http://www.citrix.com/downloads/citrix-receiver/legacy-client-software/online-plug-in-123.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4c749f9d");
  # http://www.citrix.com/English/ps2/products/product.asp?contentID=1689163
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cf71ffff");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:online_plug-in");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:ica_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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

app = 'Citrix Online Plug-in';
port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Citrix\Install\ICA Client\InstallFolder";
path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
else close_registry(close:FALSE);

exe = path + "\wfica32.exe";
ver = hotfix_get_fversion(path:exe);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT)
  audit(AUDIT_UNINST, 'app');
else if (ver['error'] != HCF_OK)
  exit(1, "Failed to obtain the file version of '" + exe + "'.");

version = join(sep:'.', ver['value']);
set_kb_item(name:'SMB/'+app+'/Path', value:path);
set_kb_item(name:'SMB/'+app+'/Version', value:version);
register_install(
  app_name:app,
  path:path,
  version:version,
  cpe:"cpe:/a:citrix:online_plug-in");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
