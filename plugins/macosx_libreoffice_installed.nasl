#TRUSTED 199aa2b58ea5d08545e6117df9565ab2d239b25b735e4eb567e935151f190553d0b1aabd02bda2f5cc1e44d6c459005146b2af468d31f036694862c3174175781ca87ab4297d65e5524f456d8bb12055ac5990c4a1214e966ed21f49805b54dccdb099a1bfd04b4692a3d73034e297c532b0f223b1a979bd1f897248bdbb204691f4e406c86591a57eb7973bd6eb65f969bc1c03defe845aa3c53f14ea959739eae64bed2030f91acae59d7ece231be54b267b1a8b3e288cb686328861e234ea55120036e652c59e591947b4c2d334ad89a6b52c267f9bf263a2b0fc80ba2069a77683c91992d40c190666b211638f2f4c2d5f0f8ef90130ad979dfe2d8c820cbf94767f300e6781b65c358283d703633870d9193b6d8b2dac85d93683e0aa43a9ffe95bf907245c579d68dea811418de208caaa693ac1e3630cd797a90a033cab64f62e9dba88313187940d82caf203f4ee1da44e7b5987ed99294a42225f502ba499874c8dbe95c8d1a3b373489c901fd3e3967551fb0e1c9ad5daeb0136d45989d5ad62f449505220d7f247c9512ed69f7265b148de868203d768ecda83d3d2a025d4615604c39a580038c60785ca0e2d1ec9478cdc303e7a6c373199548553993d7591579ef922f9985c09c3d82b3175d3068e5312d0d729e51e6c80ac0c783bde6ab25f5c87a6a6e183fb879ba1854d12f29fc47c1f6654cb643d9cbaad
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55575);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/11");

  script_name(english:"LibreOffice Detection (Mac OS X)");
  script_summary(english:"Gets LibreOffice version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host contains an alternative office suite.");
  script_set_attribute(attribute:"description", value:
"LibreOffice is installed on the remote Mac OS X host.

LibreOffice is a free software office suite developed as a fork of
OpenOffice.org.");
  script_set_attribute(attribute:"see_also", value:"http://www.libreoffice.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

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


kb_base = "MacOSX/LibreOffice";


path = '/Applications/LibreOffice.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleGetInfoString | ' +
  'tail -n 1 | ' +
  'sed \'s/[^0-9.]*\\([0-9.]*\\).*/\\1/g\'';
version = exec_cmd(cmd:cmd);

if (!strlen(version)) exit(0, "LibreOffice does not appear to be installed." + version);

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") exit(1, "The LibreOffice version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  app_name:"LibreOffice",
  path:path,
  version:version,
  cpe:"cpe:/a:libreoffice:libreoffice");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
