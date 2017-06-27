#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76309);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/19 17:45:33 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");

  script_name(english:"Attachmate Reflection Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Checks openssl.dll version.");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Attachmate Reflection install on the remote host is affected by an
out-of-bounds read error known as the 'Heartbleed Bug' in the included
OpenSSL version.

This error is related to handling TLS heartbeat extensions that could
allow an attacker to obtain sensitive information such as primary key
material, secondary key material, and other protected content.");
  # 14.1 SP3
  script_set_attribute(attribute:"see_also", value:"http://support.attachmate.com/techdocs/1708.html");
  # 2014
  script_set_attribute(attribute:"see_also", value:"http://support.attachmate.com/techdocs/2502.html");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Reflection 14.1 SP3 Update 1 (14.1.3.247) or 2014 R1 Hotfix
4 (15.6.0.660) or greater.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:attachmate:reflection");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = kb_smb_transport();
appname = 'Attachmate Reflection';

display_names = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');

in_registry = FALSE;
# Ignore Attachmate Reflection X in this plugin
foreach key (display_names)
  if (
    "Attachmate Reflection " >< key
    &&
    "Attachmate Reflection X " >!< key
  ) in_registry = TRUE;

if (!in_registry) audit(AUDIT_NOT_INST, appname);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

path = NULL;

foreach key (keys(display_names))
{
  display_name = display_names[key];

  if (
    "Attachmate Reflection " >!< display_name
    ||
    "Attachmate Reflection X " >< display_name
  )
    continue;
  key -= '/DisplayName';

  key -= 'SMB/Registry/HKLM/';
  key = str_replace(string:key, find:"/", replace:'\\');
  break;
}

# Very rough check on ver in registry
display_version_key = key + "\DisplayVersion";
display_version = get_registry_value(handle:hklm, item:display_version_key);
if (
  isnull(display_version) ||
  display_version !~ "^(14\.1\.3|15\.6)($|[^0-9])"
)
{
  RegCloseKey(handle:hklm);
  close_registry();
  if (isnull(display_version))
    audit(AUDIT_UNKNOWN_APP_VER, appname);
  else
    audit(AUDIT_NOT_INST, appname + "14.1.3.x / 2014 R1");
}

# Get install dir
install_location_key = key + "\InstallLocation";
install_location = get_registry_value(handle:hklm, item:install_location_key);
if (isnull(install_location))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_PATH_NOT_DETERMINED, appname);
}
RegCloseKey(handle:hklm);

item = eregmatch(pattern:"^(.+\\)[^\\]*$", string:install_location);
if (isnull(item))
{
  close_registry();
  audit(AUDIT_PATH_NOT_DETERMINED, appname);
}
close_registry(close:FALSE);

path = item[1];

# At the least, make sure a file exists
# to verify the registry info a bit
exe = path + "openssl.dll";
exe_exists = hotfix_file_exists(path:exe);
hotfix_check_fversion_end();
if (!exe_exists) audit(AUDIT_FN_FAIL, "hotfix_file_exists", "data that indicates the file '"+exe+"' is no longer present.");

# Parse out numeric version from registry entry version
# Registry version is formatted like :
# major.minor.{sp}{build}
# where {sp} is one digit (for now) and {build} is three
matches = eregmatch(string:display_version, pattern:"^(\d+)\.(\d+)\.(\d+)(\d{3})");
if (matches)
{
  major = matches[1];
  minor = matches[2];
  sp    = matches[3];
  build = matches[4];
  version = major + "." + minor + "." + sp + "." + build;
}
else
  audit(AUDIT_UNKNOWN_APP_VER, appname);

# 14.1.3.000 is 14 SP3 (earliest vuln)
# 15.6.0.000 is 2014 R1 (earliest vuln)
# Vendor states 14.1.3.247 / 15.6.0.660 is main app fix ver
if (
  version =~ "^14\." && ver_compare(ver:version, fix:"14.1.3.247", strict:FALSE) < 0
  ||
  version =~ "^15\." && ver_compare(ver:version, fix:"15.6.0.660", strict:FALSE) < 0
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + appname +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : Reflection 14.1 SP3 Update 1 (14.1.3.247) / 2014 R1 Hotfix 4 (15.6.0.660)' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, display_version);
