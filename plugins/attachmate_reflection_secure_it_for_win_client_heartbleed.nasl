#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73965);
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

  script_name(english:"Attachmate Reflection Secure IT Windows Client Information Disclosure (Heartbleed)");
  script_summary(english:"Checks openssl.dll version.");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Attachmate Reflection Secure IT Windows Client install on the
remote host contains a component, Reflection FTP Client, which is
affected by an out-of-bounds read error, known as the 'Heartbleed Bug'
in the included OpenSSL version.

This error is related to handling TLS heartbeat extensions that could
allow an attacker to obtain sensitive information such as primary key
material, secondary key material, and other protected content.");
  script_set_attribute(attribute:"see_also", value:"http://support.attachmate.com/techdocs/2288.html");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Reflection for Secure IT Windows Client 7.2 SP3 Update 1
(version 7.2.3.222) or greater.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:attachmate:reflection_for_secure_it_client");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

port = kb_smb_transport();
appname = 'Attachmate Reflection for Secure IT Windows Client';

display_names = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');

in_registry = FALSE;
foreach key (display_names)
  if ("Attachmate Reflection for Secure IT Client" >< key) in_registry = TRUE;

if (!in_registry) audit(AUDIT_NOT_INST, appname);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

path = NULL;

foreach key (keys(display_names))
{
  display_name = display_names[key];

  if ("Attachmate Reflection for Secure IT Client" >!< display_name) continue;
  key -= '/DisplayName';
  key -= 'SMB/Registry/HKLM/';
  key = str_replace(string:key, find:"/", replace:'\\');
  break;
}

# Very rough check on ver in registry
# If not in paranoid mode, and no version available
# from the registry or version is not 7.0.x - 7.2.x,
# then exit.
display_version_key = key + "\DisplayVersion";
display_version = get_registry_value(handle:hklm, item:display_version_key);
if (
  (
    isnull(display_version) ||
    display_version !~ "^7\.[012]($|[^0-9])"
  )
  && report_paranoia < 2
)
{
  RegCloseKey(handle:hklm);
  close_registry();

  if (isnull(display_version)) audit(AUDIT_UNKNOWN_APP_VER, appname);
  else
    audit(AUDIT_NOT_INST, appname + "7.0.x through 7.2.x");
}

# Get install dir
install_location_key = key + "\InstallLocation";
install_location = get_registry_value(handle:hklm, item:install_location_key);
RegCloseKey(handle:hklm);
if (isnull(install_location))
{
  close_registry();
  exit(1, "Unable to obtain install path from registry key : '"+install_location_key+"'.");
}

item = eregmatch(pattern:"^(.+\\)[^\\]*$", string:install_location);
if (isnull(item))
{
  close_registry();
  exit(1, "Unable to obtain install path from registry key : '"+install_location_key+"'.");
}

path = item[1];

if (isnull(path))
{
  close_registry();
  exit(1, "Unable to obtain install path from registry key : '"+install_location_key+"'.");
}
close_registry(close:FALSE);

exe = path + "openssl.dll";

ver = hotfix_get_fversion(path:exe);
err_res = hotfix_handle_error(
  error_code   : ver['error'],
  file         : exe,
  appname      : appname,
  exit_on_fail : TRUE
);
hotfix_check_fversion_end();

version = join(ver['value'], sep:".");

# Vendor patch contains Openssl.dll version 14.1.411.0
if (ver_compare(ver:version, fix:"14.1.411.0", strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + appname +
      '\n  File              : ' + exe +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 14.1.411.0' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname);
