#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32395);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/03/07 16:39:32 $");

  script_name(english:"Foxit Reader Detection");
  script_summary(english:"Checks for Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Foxit Reader, a free PDF file viewer, is installed on the remote
Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/products/pdf-reader/");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

name = "Foxit Reader";

# All of the currently know registry paths
regkeys = make_list(
            "SOFTWARE\Foxit Software\Foxit Reader",
            "SOFTWARE\Wow6432Node\Foxit Software\Foxit Reader",
            "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Foxit Reader_is1",
            "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Foxit Reader_is1");

# All of the current known executable names
exes = make_list("FoxitReader.exe", "Foxit Reader.exe");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

found = 0;
paths = make_list();
foreach key (regkeys)
{
  path = get_registry_value(handle:hklm, item:key + "\InstallPath");
  # Account for strange 5.4 installs. This is the uninstall hive.
  if (!path)
    path = get_registry_value(handle:hklm, item:key + "\InstallLocation");

  if (path)
  {
    # Normalize the string to avoid duplicates
    # ie- path and path\
    if (ereg(string:path, pattern:".*\\$"))
    {
      matches = eregmatch(string:path, pattern:"^(.*)\\$");
      if (!isnull(matches))
        path = matches[1];
    }

    paths = make_list(paths, path);
    found++;
  }
  else
    continue;
}

if (! found)
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, name);
}

report = FALSE;

foreach path (list_uniq(paths))
{
  foreach exe (exes)
  {
    version = hotfix_get_fversion(path:path +"\"+ exe);

    if (version['error'] != HCF_OK)
      continue;

    version = join(version['value'], sep:'.');

    register_install(
      app_name:name,
      path:path,
      version:version,
      cpe:"cpe:/a:foxitsoftware:foxit_reader");

    report = TRUE;
  }
}

RegCloseKey(handle:hklm);
close_registry();

if (report)
{
  port = kb_smb_transport();
  report_installs(port:port);
}
else
  audit(AUDIT_NOT_INST, name);
