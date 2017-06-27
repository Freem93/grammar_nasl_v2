#TRUSTED 8f561273f769fccf3d92f72b82905c0607fd6fd6e006c8807f2caa76e004e4edf7a7269b5b374e22a09f34ef40e7fe64cdf0af256b405a42244924ac3e9c0f77c9bf88bf5a75338ea6f4c4801f2b0301a08f244ed17bc25352c9e7ecbb8f6c3ff8810bf3b93d7b1085933da57c7b90e1999492825da99a5efb35496b33a13e824997fe3b5ce744fb371294f9cd6f4be7d02b5431b3a8c4df25cac3bff28e860f320a9d72cda5715691d738d4ce5a3855e413eec3edd3dcb77b6ea75a898f90bc81048fa9837f74719c8557ec419862bd26811595f327d4fa447822648ef4f3dca3a031dc0668d8dae49f6f0068f38c81f022ba9c4926666d88dee2983e9777f5b0586be9ce8771201606aadd7289cd24d692c083d9749b3caeb7c4bbd7ccc16d2f38b116a17848c32b28010b76fff714bb654fb73fa2431b9aaed01faf66e58ae0e8608398a4f7e80f2c20555d6dc85f8955eb58afe328061c78ff24813dbcdc84d68168d1448470a5162efc8cd2d826ce3b82e0ca35424e0bcffebed2014c22a2900fb1701ae0dce4ce92aeb58b7ffd5c143058452a53f4419816c86e0a54a566a7b5e6bf3d09997c61b0d977331d86807450aaea45c08dfff118fe1c45e75b770524bebfae271d1fb67b4b58eb9badce49dac639091df379829681c81735a172cc127cc17c067140f13dab4b762eb30d2d6ed0d6d3d38ef322e7dc86eab806
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58091);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/11");

  script_name(english:"Microsoft Silverlight Installed (Mac OS X)");
  script_summary(english:"Reads version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"The remote host has Microsoft Silverlight installed.");
  script_set_attribute(attribute:"description", value:
"A version of Microsoft Silverlight is installed on this host.

Microsoft Silverlight is a web application framework that provides
functionalities similar to those in Adobe Flash, integrating
multimedia, graphics, animations and interactivity into a single
runtime environment.");
  script_set_attribute(attribute:"see_also", value:"http://silverlight.net/");
  script_set_attribute(
    attribute:"see_also",
    value:"http://en.wikipedia.org/wiki/Silverlight"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
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


kb_base = "MacOSX/Silverlight";


path = '/Library/Internet Plug-Ins/Silverlight.plugin';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(0, "Silverlight does not appear to be installed.");
set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") exit(1, "The Silverlight version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  app_name:"Microsoft Silverlight",
  path:path,
  version:version,
  cpe:"cpe:/a:microsoft:silverlight");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
