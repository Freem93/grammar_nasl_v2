#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49807);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/04/18 18:20:36 $");

  script_name(english:"Foxit PhantomPDF Detection");
  script_summary(english:"Checks for Foxit PhantomPDF.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Foxit PhantomPDF (formally known as Phantom), a free PDF toolkit, is
installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/pdf-editor/");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("install_func.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

prods = make_nested_list(
  make_array(
    "key",  make_list("SOFTWARE\Foxit Software\Foxit Phantom","SOFTWARE\Wow6432Node\Foxit Software\Foxit Phantom"),
    "name", "Phantom",
    "exe",  "Foxit Phantom.exe",
    "cpe",  "phantom",
    "paths", make_list()
  ),

  make_array(
    "key",  make_list("SOFTWARE\Foxit Software\Foxit PhantomPDF","SOFTWARE\Wow6432Node\Foxit Software\Foxit PhantomPDF"),
    "name", "PhantomPDF",
    "exe",  "regkey",
    "cpe",  "phantompdf",
    "paths", make_list()
  )
);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

found = 0;

for (i=0; i < max_index(prods); i++)
{
  foreach key (prods[i]["key"])
  {
    path = get_registry_value(handle:hklm, item:key + "\InstallPath");
    # Newer installs store the binary name in the registry
    if (prods[i]["exe"] == "regkey")
    {
      exe = get_registry_value(handle:hklm, item:key + "\InstallAppName");
    }
    else
    {
      exe = prods[i]["exe"];
    }
    if (path && exe)
    {
      prods[i]["paths"] = make_nested_list(list:prods[i]["paths"], path + exe);
      found++;
    }
    else
      continue;
  }
}

if (!found)
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, "Foxit Phantom/Foxit PhantomPDF");
}

report = FALSE;
foreach prod (prods)
{
  if (!max_index(prod["paths"]))
    continue;

  foreach path (list_uniq(prod["paths"]))
  {
    version = hotfix_get_fversion(path:path);

    if (version['error'] == HCF_OK)
      version = join(version['value'], sep:'.');
    else
      version = UNKNOWN_VER;

    register_install(
      app_name:"FoxitPhantomPDF",
      path:path,
      version:version,
      cpe:"cpe:/a:foxitsoftware:" + prod["cpe"],
      extra:make_array("Application Name", "Foxit " + prod["name"])
    );

    report = TRUE;
  }
}

RegCloseKey(handle:hklm);
close_registry();

if (report)
{
  port = kb_smb_transport();
  report_installs(app_name:"FoxitPhantomPDF");
}
else
  audit(AUDIT_NOT_INST, "Foxit Phantom/Foxit PhantomPDF");
