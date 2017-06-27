#TRUSTED 0631692cdd1e8fd51b43cde686d1edb3718fd2e85a30d707c58f4b904e7a79f159692460f3464902f22c56acf9d1c41a3503289f45b62ab3cb574cb9b30c9dbee1528c20290e3280301f2e4a9aa174776facbaf6b5a40dd0a37db04e0d836344a65394cbbe602da452dd3592e4de908c2ffb671bcf35e2482fbc55ee5a1da61ee8fd0b3797528efab0a76d510d52e6fa364445fad9e81072804ba0bb4415ddf9b639a508591ac100638e8d3cf374af4ce2de5f8167e9e52e8c494ce899191b0ed75c33ad9560e58f1e9cbfbf1d6534b39b751c4d299288f72e9423b83176767ac50f1ddd5e895c6a50ba28cb6747172fb59adac429bfb251beb7e0a668e21ab96eedcd3bcf7d08494800db752292d851b36767f2fb74c9d0ca9600bfe89d23e399d97e9b4fb863b2f3f1cca5eb3b370301a090c8d9fd79f38b6d0ed439099b47cb8b8efce1df3ced0370a6fff1711edacb7eb7739ed0530043577ae5adfbbaef9f351b22b1f2ff6bbaeb70a0a71c72c6725b6f7ea04f2b0cc4a9e8e2a61a07cddee81df4cebeac00a6b5f181fe2a2c1651da97b8163efd218a7c515e01a2731b544cba3a6d7e0e5f5586cd67aa5cca7e4f806998388662b07d8757062051277396f3b2689cfa3238c8ff8e4c40c66cf05eb3fcdd2b0c319450469039b07e7e74cd5c8a8134fb918f106771faf03e9ffae79af4b9217596023df4c7e6251be4a0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65699);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/11");

  script_name(english:"Viscosity VPN Client Detection (Mac OS X)");
  script_summary(english:"Detects Viscosity VPN Client");

  script_set_attribute(attribute:"synopsis", value:"The remote host has a VPN client installed.");
  script_set_attribute(attribute:"description", value:"The remote host has the Viscosity VPN client installed.");
  script_set_attribute(attribute:"see_also", value:"http://www.sparklabs.com/viscosity/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:sparklabs:viscosity");
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

kb_base = "MacOSX/Viscosity";

path = '/Applications/Viscosity.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, "Viscosity");

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

if (version !~ "^[0-9]") audit(AUDIT_VER_FAIL, "Viscosity");
set_kb_item(name:kb_base+"/Version", value:version);

register_install(
  app_name:"Viscosity",
  path:path,
  version:version,
  cpe:"x-cpe:/a:sparklabs:viscosity");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
