#TRUSTED 89a742bb22aa51840c34d4746ca9061310fa58ddeec7c666d08506fea308b54b970eacfda8e92e1dcf084baaa06c2677544ac8dce4256483ad5de73f5a0a08203d3ad52de07f28e9100f4a9cf242bfd8950ce3e137801844cd14fd8dc1461a0811632022921ce4f37cab9161e05461f5d0b75a20c655247899b1c83bdc3eec0be6b223b0a68e9f369d18c20aabc2f6b5da8b2259e01030043b3c6d76173c7d3be47154382edf0416c067ef123e9f1fef338f954f40043757df6fb3df3876114817604439c8ef753dacd8ecd693ba4891a62bedaa2422599929529b18f3029b8497fafcc59d2383edb32d0247be17c730bee997b04dd98d3db0af27b6396645e8d5eaa3308b2e847e6b3c6f71445312990f4e8521d56c98f9b3b39ee518e1781efc10a05067d0ab21c5bc5b092d601f0a385bbd103ed82a9bfb1668aee779a0f7e1c8606767d654bf0d0dd5f63b4ef5067d6b16437e78c99e1a05d35c70ca85ad6d71f769078b55ec46f5fa7e1573fab233a43819d2afcbb49e7b80724bef4066cbc1e01e072c43dbcdb7126873b25e728e7c51be34a2377a464c9e9933be65b8c8678a1276720f48e29abb6a76160e72986aab3e9fefcb6ea813fcb9507e7c38c52ff597938a2b4ead5d1bc7c4d953f1dc198fcfb7baa13e405885660afc86c93871cf3bcc3992fa7ff26aba9a3b9e1c0bb08affc9389ce42efd7a97232e85ba
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58291);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/11");

  script_name(english:"Evernote Installed (Mac OS X)");
  script_summary(english:"Reads version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"A cloud-based note taking application is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Evernote is installed on this host. It is a cloud-based suite of
software for note taking and archiving.");
  script_set_attribute(attribute:"see_also", value:"http://www.evernote.com/evernote/");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");
include("audit.inc");
include("install_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


kb_base = "MacOSX/Evernote";


path = '/Applications/Evernote.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(0, "Evernote does not appear to be installed.");
set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") exit(1, "The Evernote version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  app_name:"Evernote",
  path:path,
  version:version);

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
