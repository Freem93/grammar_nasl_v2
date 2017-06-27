#TRUSTED 5896e51827b2c0f3d65ae06a879d567e9139c423fa560594f2bc04c4dadaa39c7fd58ca400187a4e4a2ac50693aad94e9731a2bead071ee0470da4dfc7653796650f91d26abba016667d0fa49e6c2b10bb5614872f7e3e843e9017959e555628d84d23c663923ff44170d5e6a039da3f4d1443041f90ebf563e5358b62ea770a0dc216d8c3d9a0db8a1603d85a8421680c893be3aa5076dd9a28a37674008a5dd6b3d4ba59c3d5c311e13b99caf30285dab7173c80eb519e414179a80f5ef824959d4be2410ebc2d088762e787c4a346aa93b8104a7de17051f25dd41eec4cfdf735debcc721715c6f67507fda7285058381d609538c1c65c7a75f9c427a909e8d83f2f3a905e39e1bb707e1bae545e431e2e8af4219bd9d36e8670ad2d06d8e8afbcf48550d5f3407bad67d11168b098b1a593b7f9a8e1dc0a0ec8ace8196685bb194c7891de3aa8d4f2781731d1fbdae70b0fff8e70499253ebcbbe11071cd2e9a3dd1d3b49b0da5ed05367606b18178265b6ab93dec41f87df198e450fe3c98b0b40ea71d3cc860139ad937dd983f1f3fad31986cf280e75a5821e7924cbf702564523535130a71403b441a7c2b30e5c574e3afd3d1233f66854913d1db0f64de6f37d08071d7c00d397fc4f10cbe057afe5ee28fdc2d5fcb20c10fad16a5bfb3f0bc4f97c6593c3f3d112214e5e16d495cc2ff1988c2c3305508227cb56f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61620);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/11");

  script_name(english:"Apple Remote Desktop Admin Detection (Mac OS X)");
  script_summary(english:"Reads version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"A remote management tool is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"description", value:
"Apple Remote Desktop Admin is installed on the remote Mac OS X host.
It is a tool for managing Mac computers on a network.");
  script_set_attribute(attribute:"see_also", value:"http://www.apple.com/remotedesktop/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:apple_remote_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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
if (!get_kb_item("Host/MacOSX/Version"))audit(AUDIT_HOST_NOT, "running Mac OS X");

kb_base = "MacOSX/Remote_Desktop_Admin";

path = '/Applications/Remote Desktop.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, "Apple Remote Desktop Admin");

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") exit(1, "The version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  app_name:"Apple Remote Desktop Admin",
  path:path,
  version:version,
  cpe:"cpe:/a:apple:apple_remote_desktop");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
