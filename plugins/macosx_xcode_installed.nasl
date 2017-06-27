#TRUSTED b212567c1eeb86d24868979aeb0ccb9600adcabcefb6b7f4dcedb924d30ebf73753afb37c8a217da3df28e4392b6d1a382f885a9999bf1b1b6194eed4de7ea4d3c2cef5fa07d05fc41e539d3b0bf1eb4a9654efca5c8d2cfb6eb611e15dc3755d30425986754b413a53839b62742e2bb648aa522f9163c73a27157e6eb06818547a7cded185a10912262506659174e0c05e4a7f0ec6b8ca7f06ce240b2fd669c4f7b4ad900f94aae173b2ff927ab8b7b555e6ca92fba7251345a9aad2c28029e4da0e769f16dd1e18fbb69a9baff7573db2209806746ea3c940d6a7a56e1f8a89aab253d7f862964164417f2aeeeb5a0471dfb184bfad91946cb8d71a8d1a99558650f277b816cb7904f021239df33d7a7752931a6c4ab889d24989b249c640ed9136dc19cf484f1c809a15fe0c2d3dfb7280e2db7232c9e897fa4bb5d3ac898c513b2354e5c5b48c8e397116461044ed4aa7351086c264f0a1b40b8d211cb2a1578c7e0eea76801b715e79639c08f1b064487f50411bdaf38aa6d4e70b21dff7f43ff876d08fb60c81bb435fd5b9f215ae78dc571346414b0ced991eb73b21a52fa503f29c00e9877e461a870587d14552bd7ae375990f042afc4370f9633ede9efe9009ccdaa7c682f25e6016cfcdbc847f0c40fb2a88d20e92b432349f7ce94e24438257a100ba337070cb6d1a754ec4933eebeca7a66373a4db1d99b4bc8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61412);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/01/19");

  script_name(english:"Apple Xcode IDE Detection (Mac OS X)");
  script_summary(english:"Detects Apple's Xcode IDE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an integrated development environment installed.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has Apple Xcode installed. Xcode is a
development environment for creating applications that will run on
Apple products.");
  script_set_attribute(attribute:"see_also", value:"https://developer.apple.com/xcode/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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
if (!os) audit(AUDIT_HOST_NOT, "running Mac OS X");

appname = 'Apple Xcode';

kb_base = "MacOSX/Xcode/";

# some default directories Xcode may be installed into
xcode_pathlist = make_list('/Applications/Xcode.app/Contents/Developer',
                           '/Applications/Xcode.app',
                           '/Developer/Applications/Xcode.app/Contents/Developer',
                           '/Developer/Applications/Xcode.app',
                           '/Developer');

xcode_b_pathlist = make_list('/Applications/Xcode-Beta.app/Contents/Developer',
                             '/Applications/Xcode-Beta.app',
                             '/Developer/Applications/Xcode-Beta.app/Contents/Developer',
                             '/Developer/Applications/Xcode-Beta.app');

# get path of current Xcode install being used (if possible)
# and add it to the path list
# this command first appeared in Xcode 3.0
cmd = 'xcode-select -print-path';

xcode_path = exec_cmd(cmd:cmd);

if (
  'Error: No Xcode is selected' >!< xcode_path &&
  xcode_path[0] == '/' && # valid paths should start with /
  !isnull(xcode_path)
) xcode_pathlist = make_list(xcode_pathlist, xcode_path);

xcode_pathlist = list_uniq(xcode_pathlist);
install_num = 0;
report = '';

foreach path (xcode_pathlist)
{
  xcode_build = path + '/usr/bin/xcodebuild';
  command_result = exec_cmd(cmd:xcode_build + ' -version');
  if (isnull(command_result) ||'Xcode' >!< command_result) continue;

  cmd = xcode_build + ' -version | head -1 |' +
        'sed \'s/.*Xcode \\(.*\\)/\\1/g\'';

  version = exec_cmd(cmd:cmd);

  item = eregmatch(pattern:"^[0-9\.]+$", string:version);
  if (isnull(item)) continue;

  set_kb_item(name:kb_base+install_num+'/Path', value:path);
  set_kb_item(name:kb_base+install_num+'/Version', value:version);

  register_install(
    app_name:appname,
    path:path,
    version:version,
    cpe:"cpe:/a:apple:xcode");

  report += '\n  Path    : ' + path +
            '\n  Version : ' + version +
            '\n';
  install_num ++;
}

foreach path (xcode_b_pathlist)
{
  xcode_build = path + '/usr/bin/xcodebuild';
  command_result = exec_cmd(cmd:xcode_build + ' -version');
  if (isnull(command_result) ||'Xcode' >!< command_result) continue;

  cmd = xcode_build + ' -version | head -1 |' +
        'sed \'s/.*Xcode \\(.*\\)/\\1/g\'';

  version = exec_cmd(cmd:cmd);

  item = eregmatch(pattern:"^[0-9\.]+$", string:version);
  if (isnull(item)) continue;

  set_kb_item(name:kb_base+install_num+'/Path', value:path);
  set_kb_item(name:kb_base+install_num+'/Version', value:version);

  register_install(
    app_name:appname+'-Beta',
    path:path,
    version:version,
    cpe:"cpe-x:/a:apple:xcode_beta");

  report_b += '\n  Beta path    : ' + path +
              '\n  Beta version : ' + version +
              '\n';
  install_num ++;
}

if (report)
{
  set_kb_item(name:kb_base+'NumInstalled', value:install_num);
  set_kb_item(name:kb_base+'Installed', value:TRUE);

  if(!empty_or_null(report_b))
    report += report_b;

  if (report_verbosity > 0) security_note(port:0, extra:report);
  else security_note(0);
}
else audit(AUDIT_NOT_INST, appname);
