#TRUSTED 082a9b442d2166adc8c72da688eb8fc9cb05d86a3ece02b770ade95b0d1688f53bb3e1290cdb8653378d8cc36c385cab74b846356296e821230043a75ba252c952f640317c3d47662d40e395aa7e1c99b85213ab8fbbef3cf4f115c31b31f087665b663d9d87efed5557291d9bbf780c12d21ee8a3175359ea70da11f8e1577fbf95e177e1482a01701b152b0e71f31f60156e9b53b5da8cf0a389829180e05008d6ffc5d058c59c12dcdf65f7cfc98225447bf774d856d47fdc533687bf59ff1653fca165d114007b87524e98296890787129bcfa16efb32a73a2ef40313026e30d86bea8e7a62051b4998a2a003e436774069ea59c2a6db5ca4ce3c7f672c59c9aae921b85662b467e6ebf22d3fd96301246ee36ea364a4640aa8b1eccb26a778b154f77bfbe5dacfadadc31a644d181ea1927e066f434e6aec34eef245d1da178f8c3eea1a8a2869e63d56b6861decaad344c44961f11aecd3ac6acfc5ebbb8105419007e47a044200d5e758588531740fb905271d993488291fb317510f5bc3639923cef82584c8f0682709ab4823bf3a107da74edc6f75f20d45af09af8926ec3ef3e0fa65198c21b687648e854e5ee3e341b3dd08495224c00d2fedb9db42797e4a878ae59831c08dd3a92441c5b358cac0ff01840fd2772884f1addfbf8846d37a2d57c476fb52b704c05c2b2b8a9f51f1fe66d60880fca7b969c1a9e
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(53843);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2011/05/09");

  script_name(english:"Skype for Mac Installed (credentialed check)");
  script_summary(english:"Gets Skype version from Info.plist");

  script_set_attribute(
    attribute:"synopsis",
    value:"Skype is installed on the remote Mac OS X host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Skype, a peer-to-peer Voice Over IP application, is installed on
the remote Mac OS X host.

Due to the peer-to-peer nature of Skype, any user connecting to the 
Skype network may consume a large amount of bandwidth."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://developer.skype.com/MacSkype"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


global_var debug_level;

include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0, "The 'Host/MacOSX/packages' KB item is missing.");

plist = "/Applications/Skype.app/Contents/Info.plist";
cmd = string(
  "cat '", plist, "' | ",
  "grep -A 1 CFBundleShortVersionString | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec_cmd(cmd:cmd);
if(isnull(version)) exit(0, "Skype is not installed.");
if (version !~ "^[0-9]") exit(1, "Failed to get the version - '" + version + "'.");

# nb: older versions (eg, 1.3.0.14) have their version info in a different spot.
if (version =~ "^0\.")
{
  cmd = string(
    "cat '", plist, "' | ",
    "grep -A 1 CFBundleVersion | ",
    "tail -n 1 | ",
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
  );
  version2 = exec_cmd(cmd:cmd);
  if(version2 =~ "^1\.") version = version2;
}
set_kb_item(name:"MacOSX/Skype/Version", value:version);

gs_opt = get_kb_item("global_settings/report_verbosity");
if (gs_opt && gs_opt != 'Quiet') security_note(port:0, extra:'\n  Version : ' + version + '\n');
else security_note(0);
