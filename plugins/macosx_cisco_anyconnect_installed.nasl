#TRUSTED 7e05187f79a6f58104b4fc5c6a9e6cd55ce4cc591791ae8f2f552d19882cba7baa7142be694110c09980ed0e1ba1dc51ea9f614e8bca5c36d8dffb2137867fcc415841796cff553b622a947d1134a09f593dea478a76c5c9a1bc3a6572c1805df8f0906c0ce09f26dc849bec5235d87748e9e0fbeeec71da741a36994735010dc8eb433954a8c95689fd6f55097d2f8f7db77776f344dc2495a2811a134800b708c74205dc4582f6a86bd4aa9eceab274ed01c74b7eeeb5727346cfb218cc29dcf3808259026319600043f7038cdea0b43016dfe841ef1f2c566cba0c51223c438bd9e05bdf9daf36990cec220002990ee88786e48d91fdf6483d0736c13f91aa0eeeb4f839560efe8b38c15b0f671cbf9334f6ee44f090d8eb0f528a00073c169d228089afb605779394546096ed4ced7f5879c708a67ddbb96754ee94fec78265132652ec3b2f232c68deb540b4c49e256f68609875a85c410d2afc1105a27372533033e0f8cf2851577e6ad55b33042e0a360f36f6312918e262c70d7ed6b2ca12ca805c0587ba94d6321f15493e85504b92dc83575f5f0c607f46dee42c6f8c931206a065699118482abfefafe7db81b36576fccd41a844fe04f3434e10cbf35ed3b90adcec3c7429b42def6a73557759fafd441484d2b19ff67efb087ba1811862d7c93eb4d44c1ba8dc2ea45573a1e6927df3a431b822627dae752e718
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59822);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/03/03");

  script_name(english:"MacOSX Cisco AnyConnect Secure Mobility Client Detection");
  script_summary(english:"Checks if the AnyConnect client is installed");

  script_set_attribute(attribute:"synopsis", value:"There is a VPN client installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Cisco AnyConnect Secure Mobility Client (formerly known as Cisco
AnyConnect VPN Client) is installed on the remote host. This software
can be used for secure connectivity.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps10884/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");

kb_base = "MacOSX/Cisco_AnyConnect";
appname = "Cisco AnyConnect Secure Mobility Client";

# 3.x check
# Check that the app is really installed
# and grab a detailed version from its
# uninstall app.
path  = '/Applications/Cisco/Cisco AnyConnect Secure Mobility Client.app';
plist = '/Applications/Cisco/Uninstall AnyConnect.app/Contents/Info.plist';

# this works for 3.x >= 3.1.06073
plist_field = 'CFBundleShortVersionString';
cmd = 'if [ `grep ' + plist_field + ' "' + path + '/Contents/Info.plist" 2>/dev/null` ] ; ' +
      'then ' +
        'plutil -convert xml1 -o - \''+plist+'\' | ' +
        'grep -A 1 ' + plist_field + ' | ' +
        'tail -n 1 | ' +
        'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\' ; ' +
      'fi';
version = exec_cmd(cmd:cmd);

# 3.x < 3.1.06073 uses a slightly different plist field
if (isnull(version))
{
  plist_field = 'CFBundleVersion';
  cmd = 'if [ `grep ' + plist_field + ' "' + path + '/Contents/Info.plist" 2>/dev/null` ] ; ' +
      'then ' +
        'plutil -convert xml1 -o - \''+plist+'\' | ' +
        'grep -A 1 ' + plist_field + ' | ' +
        'tail -n 1 | ' +
        'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\' ; ' +
      'fi';
  version = exec_cmd(cmd:cmd);
}

# detect 2.x installs
if(isnull(version))
{
  path = '/Applications/Cisco/Cisco AnyConnect VPN Client.app';
  bin_path = '/opt/cisco/vpn/bin/';
  cmd = bin_path + 'vpn -v | grep "(version" | sed \'s/.*(version \\(.*\\)).*/\\1/g\'';
  version = exec_cmd(cmd:cmd);
}

# And exit if all attempts have failed
if (!strlen(version))
  audit(AUDIT_NOT_INST, appname);

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") exit(1, "The " + appname + " version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  app_name:appname,
  path:path,
  version:version,
  cpe:"cpe:/a:cisco:anyconnect_secure_mobility_client");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
