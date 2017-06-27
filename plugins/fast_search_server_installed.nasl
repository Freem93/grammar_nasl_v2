#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60154);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:32 $");

  script_name(english:"Microsoft FAST Search Server Installed");
  script_summary(english:"Checks if the software is installed");

  script_set_attribute(attribute:"synopsis", value:"A search application is installed on the remote Windows host.");
  script_set_attribute(
    attribute:"description",
    value:
"Microsoft FAST Search Server, an enterprise search application, is
installed on the remote host."
  );
  # http://sharepoint.microsoft.com/en-us/product/capabilities/search/Pages/Fast-Search.aspx/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a8ad6ad");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:fast_search_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_ports(139, 445);
  script_require_keys("SMB/Registry/Enumerated");

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\FAST Search Server\Setup";
names = make_list('Path', 'ProductType');
values = get_values_from_key(handle:hklm, entries:names, key:key);
path = values['Path'];
prodtype = values['ProductType'];
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, 'FAST Search Server');
}
else
  close_registry(close:FALSE);

exists = hotfix_file_exists(path:path + "\bin\fastsearch.exe");
hotfix_check_fversion_end();

if (!exists)
  audit(AUDIT_UNINST, 'FAST Search Server');

report = '\n  Path : ' + path;
set_kb_item(name:'SMB/fast_search_server/path', value:path);

extra = make_array();
if (!isnull(prodtype))
{
  report += '\n  Product type : ' + prodtype;
  set_kb_item(name:'SMB/fast_search_server/prodtype', value:prodtype);
  extra['Product Type'] = prodtype;
}

register_install(
  app_name:'FAST Search Server',
  path:path,
  extra:extra,
  cpe:"x-cpe:/a:microsoft:fast_search_server");

if (report_verbosity > 0)
{
  report += '\n';
  security_note(port:kb_smb_transport(), extra:report);
}
else security_note(kb_smb_transport());
