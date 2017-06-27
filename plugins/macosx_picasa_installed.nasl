#TRUSTED 1f026ced20538e99bbfb7dcca653c9596b16e1c43a50ecfe854e6364f5f7734f5361a532cc72067ebd9ccf7205f4b0cbfefa7a23ae67d591701c0175628095be1adffa1baf8e1fa0a543011565d3f0c08233de98de2def8d5565322589b6680933ee00bb6d1f3a95d0c7152fa0df324c2b0c88781a98ddc60bbf696a335bdf9dee38a16115b4b53fd813152790077ff4a39bf04dae462ba96e9f20eb848f31df281c730be98c34c0928fdb2d61ec6d452e11f0d50daa91f9b874aebb671a871887b5d200c1b3895b913ab8e067917dc8977672b6228028c881ba4c91f9332c8077e254f9c9aa8557963cd1891c0afad015b9b8fc1978e3e41eb197f00adb818d3a0885a1e56ef1ca8aa265a6ec0a1f8140493303d03ef12e72264377a0d0781d31d5cc6e8ec48109bb5e3d9dcde65f0cf14d46a2f806299402a115b8bab8039a438ca8b719867b63216e3b19975119ca6b411bb02d50850849fb38efb64e72b631f11bae98f7126b6fba0bd82c10ca42b92248db97bb016ba9c6d0f2a0e15a6a178fb2669e49d84b85eb5258b9de092c3c6ef7c6a9851fa8624be859ac4ed76be3ac67300ac5cc439210d9f8888fd11b0bb605f60ebee87fdfd0e182aaf4e9b17fa3a59b2eb12bafcdac4a196db8f889b8d7a1d126a8c3972395667e659a13e22eeeb7b395baa49e55af1e2e18bc65bc107d89393b5428bbd439208c57058702
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65924);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/11");

  script_name(english:"Google Picasa Installed (Mac OS X)");
  script_summary(english:"Gets Google Picasa version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"Google Picasa is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"description", value:"Google Picasa is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"see_also", value:"http://www.google.com/picasa/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:picasa");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

appname = "Google Picasa";
kb_base = "MacOSX/Picasa";

path = '/Applications/Picasa.app';
plist = path + '/Contents/Info.plist';
cmd = 'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);

if (!version)
{
  cmd = 'cat \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
  version = exec_cmd(cmd:cmd);
}

if (!strlen(version)) audit(AUDIT_NOT_INST, appname);

if (version !~ "^[0-9][0-9.]+$") audit(AUDIT_VER_FAIL, appname);

set_kb_item(name:kb_base+"/Installed", value:TRUE);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

version_ui = ver[0] + "." + ver[1] + " Build " + ver[2] + "." + ver[3];

set_kb_item(name:kb_base+"/Version", value:version);
set_kb_item(name:kb_base+"/Version_UI", value:version_ui);
set_kb_item(name:kb_base+"/Path", value:path);

register_install(
  app_name:appname,
  path:path,
  version:version,
  display_version:version_ui,
  cpe:"cpe:/a:google:picasa");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version_ui + '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
