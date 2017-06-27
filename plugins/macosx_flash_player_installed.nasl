#TRUSTED a955e178cdc3ad16e4f5cd2f9b8618148274513dc4d2279b90179a2640d2146e51fe9367735d6479004a07a1978b9f48304a12481d55154ce5790377f0fffd33535f27995b1dd90e33101ae56c7229aee80afe4f535a4505fd152258dbe1315a78cb593866384f86a9b9681bf12ed2d5ef20a422d99b7b9bd2855e1749ed5972bc9dc48947e91eef445df37d0ff9e380e6ea77f31858c5b92c9e1a10cdecaff9d491cee8a4ba5f584568e097c521a3ff4cce6c565162d1f876c2b96ddfbc6c7e035248f0310cbe36968cd59a46ccca8724e3aa2eaa75f2befb9eb3738775c79ab3fdb8fc0c534473407bea61f49016d1a3cb6761d1ff9cb8567414529b2b71e691f1439359932dbe80eeaf0397e139c11fb571c044fa971ba0decc93dc48edbd311237ce0eb70645d13c7b754de1bd53f1c8fa4ed448b196f681536cdc3d53c8244fe2ac1a275ae2e7febd7fa50143f9b10112c908608a5316bd791fe6c21a4b773f57de30d540c3fa169670474c429d6a4ce5fa8fcfa9a21b50da2b91235743f703e23ef9777e7507d01f50f2c12e6f4344795ada7cee01a17fda6d6e8719de5c5dad495aed5968238433720ee4ea2ab315f6bff24246315471a8d985f2b0198f4905bdda9b4fb4b87a699f4e60c95d13eb7c0724cc2b1af3e6708e8e8ccd4d4806bc9ba83cb95f01b343622d944025d372bd19898329c76e7a3b98b1fa4d33
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53914);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/11");

  script_name(english:"Adobe Flash Player for Mac Installed");
  script_summary(english:"Gets Flash Player version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a browser enhancement for displaying
multimedia content.");
  script_set_attribute(attribute:"description", value:"Adobe Flash Player for Mac is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/flashplayer/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("audit.inc");
include("install_func.inc");


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0, "The 'Host/MacOSX/packages' KB item is missing.");

path = "/Library/Internet Plug-Ins/Flash Player.plugin";
plist = path + "/Contents/Info.plist";
cmd = string(
  "cat '", plist, "' | ",
  "grep -A 1 CFBundleShortVersionString | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec_cmd(cmd:cmd);
if (isnull(version)) exit(0, "Flash Player is not installed.");
if (version !~ "^[0-9]") exit(1, "Failed to get the version - '" + version + "'.");

set_kb_item(name:"MacOSX/Flash_Player/Path", value:path);
set_kb_item(name:"MacOSX/Flash_Player/Version", value:version);

register_install(
  app_name:"Flash Player",
  path:path,
  version:version,
  cpe:"cpe:/a:adobe:flash_player");

if (report_verbosity > 0)
{
  report = '\n  Path    : ' + path +
           '\n  Version : ' + version +
           '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
