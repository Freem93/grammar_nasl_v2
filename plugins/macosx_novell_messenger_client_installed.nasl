#TRUSTED 4f85f236dfedc35e5cb771d3df89713f7231fc92a4500162b147f193f6d34652bfb2d5b98ecaa81ab5717ebefdfe906261302bb66edabc881e30871d1de45bf92bb0fd07a626d5c7651c19ff373d42a711d4e182f63b544910bc7345d624c9946d0e0fe9b6602b8802c482d98bef6f707acb3f9b3b7587c2bb7fd8744c5604f7b22e3caabbf6d3dc24a03d4744fb3fb0cf8d9428c9068bd4edfbe0d7354c77044ff922f08f18fe32cf8bd2a51af3fbbdfe6e2013b6a52f941ca2dcac2480cb0d15813d00a10b3db661b65537c27435dd53c5da70987a190d6fe87b3f19426d6157aaa0d70979994f6f00e7d65841d078f79aaabf41f41b5f6d624117f80d489121eed37c91dbc7086c900ffcba73dede7ac9bf4d37f8bee4835193738e4fc18d9fbbb896a2da28196e2ff0bef4f77f902ed26e07aa17ff01f192a39578d1b0199d91a67d727bf49ba0e4c877d470146e1acd28b4236d104491b1b11fbd0375512c2489a88443820e8c564aca00983540eb016264c77ad15e77836e342dcc61f3e9a129996c3f2c843c45bd0d044e647c4f7ca3350257295f44d4ca58ef29f4f728f17a5d59d4daf6fd6ed8bc5fc4e4610c6af083a816f67a1fe9c283b0c035f2be53ab286490d9a170996d5927d2f7c0aca504ba656c9cea57dc2a2347f32ba73635c5a90dbcdf8c4821dc5c5ba1ab83d1c1b70ac1359dca1d189a754c1e4998
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65673);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/11");

  script_name(english:"Novell Messenger Client Detection (Mac OS X)");
  script_summary(english:"Detects installs of Novell Messenger (formerly GroupWise Messenger) Client");

  script_set_attribute(attribute:"synopsis", value:"The remote host has an instant messaging client installed.");
  script_set_attribute(attribute:"description", value:
"The remote host has Novell Messenger (formerly GroupWise Messenger)
client installed. This is an instant messaging client based on Novell
eDirectory.");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/documentation/novell_messenger22/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:messenger");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_messenger");
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

kb_base = "MacOSX/Novell_Messenger_Client";

path = '/Applications/Messenger.app';
plist = path + '/Contents/Info.plist';

# Messenger.app is not very unique, so double check this is a
# Novell Product
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | grep \'string\'';
plist_string_contents = tolower(exec_cmd(cmd:cmd));
if("novell" >!< plist_string_contents && 'groupwise' >!< plist_string_contents)
  audit(AUDIT_NOT_INST, "Novell Messenger Client");

cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);

if (!strlen(version)) audit(AUDIT_NOT_INST, "Novell Messenger Client");

set_kb_item(name:kb_base+"/Installed", value:TRUE);

if (version !~ "^[0-9]") audit(AUDIT_VER_FAIL, "Novell Messenger Client");

set_kb_item(name:kb_base+"/Version", value:version);
set_kb_item(name:kb_base+"/Path", value:path);

register_install(
  app_name:"Novell Messenger Client",
  path:path,
  version:version,
  cpe:"cpe:/a:novell:messenger");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
