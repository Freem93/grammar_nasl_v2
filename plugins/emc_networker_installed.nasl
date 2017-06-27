#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62945);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/10 14:57:38 $");

  script_name(english:"EMC NetWorker Installed");
  script_summary(english:"Checks the registry / filesystem for EMC NetWorker.");

  script_set_attribute(attribute:"synopsis", value:
"A backup and recovery application is installed on the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"EMC NetWorker (formerly Legato NetWorker), a suite of enterprise level
data protection software, is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.emc.com/data-protection/networker.htm");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:networker");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:legato_networker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Legato\Networker";
item = get_values_from_key(handle:handle, key:key, entries:make_list('Path'));
if(empty_or_null(item))
{
  close_registry();
  audit(AUDIT_NOT_INST, 'EMC NetWorker');
}
path = item['Path'];
build = 0;

key = "SOFTWARE\Legato\Networker\Release";
regversion = get_registry_value(handle:handle, item:key);
if (!isnull(regversion))
{
  build = int(ereg_replace(string:regversion, pattern:'^.*Build\\.([0-9]+)$', replace:"\1"));
  regversion = ereg_replace(string:regversion, pattern:'^([0-9\\.]+)\\.Build.*$', replace:"\1");
}
RegCloseKey(handle:handle);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, 'EMC NetWorker');
}
close_registry(close:FALSE);

fileName        = hotfix_append_path(path:path, value:"bin\winworkr.exe");
fileName_nmm    = hotfix_append_path(path:path, value:"bin\EMC.NetWorker.dll");
fileName_nmmedi = hotfix_append_path(path:path, value:"bin\nwmedisan.dll");

item = hotfix_get_fversion(path:fileName);
if (item['error'] != HCF_OK)
{
  # If we couldn't get the version from the file, it may be a permissions issue
  # See if we got it from the registry.
  if (isnull(regversion))
     hotfix_handle_error(error_code:item['error'], appname:'EMC NetWorker', file:fileName, exit_on_fail:TRUE);
  else version = regversion;
}
else version = join(item['value'], sep:".");

extra = make_array();
###################################################
# Gets Module for Microsoft Apps Version
item  = hotfix_get_fversion(path:fileName_nmm);
if (item['error'] == HCF_OK)
{
  version_nmm = join(item['value'], sep:".");
  extra["Module for Microsoft Applications Version"] = version_nmm;
}
###################################################
# Gets Module for MEDITECH
item = hotfix_get_fversion(path:fileName_nmmedi);
if (item['error'] == HCF_OK)
{
  version_nmmedi = join(item['value'], sep:".");
  extra["Module for MEDITECH Version"] = version_nmmedi;
}

# If we got a build number from the registry
if (build > 0)
  extra["Build"] = build;

hotfix_check_fversion_end();

# Don't register install with an empty array
if(max_index(keys(extra)) == 0) extra = NULL;

register_install(
  app_name:'EMC NetWorker',
  path:path,
  extra:extra,
  version:version,
  cpe:"cpe:/a:emc:networker"
);

report_installs();
