#TRUSTED 551c3b5d7fc0a681c4b8826979be1bea36a0e6f8a33bb3c86cce795821109d1541a8abcff7c01e4b349a67da752ac9be92b8ae1c3106e11f92c93fe9ea6e2e4a6c6656f38f003222b18321d7a2fbe877d74362b1db3f4e4d5b4d59ea67171a920838d6fdc8920bc7d7dbf17fb439030800d35df23f3f11a2f65ee8fa3c80b74e30062d4a74817fddf715fca1b3b5eacfbf6af4221cff67d86f43a6260322e3234f0ddbffb18136d0944ff594c8db1376a7cdf29737e9afc7639eb46336c3b4d10351e541d3e88c8ff2194512566b0c0276062cdd16eb32f2c1d218c47713c5eee90ff90f42d81577d7ff97230551c72744d5fefbb0b7707b1c36f216a3d8d0dd05e4e28c80dee50de694076971b3f41e5b3a721dce59b7545dde7d4b23dbc6c8a18d49ad0b90325762e250fb5c4482a59a908205ca59914d6555434b09573c917c70888ad069216ef86158b9dc0d105eced449c83287b8125b04a717ded6a65aa46387e2fd08d679ce7a9686eb8421eb6e33740a9e2b5257e317b8179f5c61678977071b7dc12bdf6d7ee122a31daae7f2da7e8f36525d38816c1326b696bcbcc3c0c95ab772b57d1b0303bce6a2cf0c0c61b483a3e55c5f6fae91022dff38900220ea8961a9200ed9e373707fb9b962b4c507badc704f98231318fbf5dd79edcabb1ed37ff7c65895d700d696438a652db2112bedc558be3dc1d4685a026bc2
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(55435);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2011/06/27");

  script_name(english:"Dropbox Installed (Mac OS X)");
  script_summary(english:"Gets Dropbox version from Info.plist");

  script_set_attribute(
    attribute:"synopsis",
    value:"There is a file synchronization application on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Dropbox is installed on the remote Mac OS X host.  Dropbox is an
application for storing and synchronizing files between computers,
possibly outside the organization."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.dropbox.com/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Ensure that use of this software agrees with your organization's
acceptable use and security policies."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dropbox:dropbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


kb_base = "MacOSX/Dropbox";


plist = "/Applications/Dropbox.app/Contents/Info.plist";
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(0, "Dropbox does not appear to be installed.");
set_kb_item(name:kb_base+"/Installed", value:TRUE);

if (ereg(pattern:"^Dropbox ", string:version)) version = version - "Dropbox ";
if (version !~ "^[0-9]") exit(1, "The Dropbox version does not look valid (" + version + ").");
set_kb_item(name:kb_base+"/Version", value:version);

if (report_verbosity > 0)
{
  report = 
    '\n  Path    : /Applications/Dropbox.app' +
    '\n  Version : ' + version + '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
