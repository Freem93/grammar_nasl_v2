#TRUSTED ac870b0053efe123897b3d9cd33d5ba4be7d615d299ba0fd3949e1877a5fa566a9aff81948673eb1d169b730fda029c9c25a51b3fd2a10c483d1b072c7c652d4cf81cabc740200ebe28c3f048e7c60cd6c80ed0e9bcd416ac59c5088c3c31fdb5a2dcd50f89e6050c80fcc937f106e40859ebc28d606f2f3c67719330a81e218e799ec71238da8664076b002f7350c93ac4e2089a27387d51f38705a9a2cf64ab03786a1b586b852a6d3a15dd5b5dc45b1b8ba760f30bf0a4a5beba7d4c01186f443aa36eca41ba5d0c106fe49c350fa6b36c8e6b0f54d766e2ec4383c4d6401d798dc9f6d208424e5c3507e02b143b996aa68fc3ca82023dd319c6a7193a3203e560bcaa106d77084e859c4e66a4bc8f0a2fd5e242234f3abcb22bb3f6137ead74d31b1d8e9bb957e3814b448e3e61a71a0dfa1c07af64abc75b1074eaecbe5ce8442a125f3d25a613bf465173469517683272838f845a42fe10f9628ee3f5bd8491181bcd5882368e5f7e83a3bffeb01f7645c0cf0ce3cf945264eca8a00cedd08d7a4aa69fa258ff80f85f8ec5ba2834ab622c96dcfb8dd8e3aeb1e9425c70f7b263210b593aabdacd5c30193bd929479d0a05f73fec72ae302aaffcae4e4e4d7e50e7c963322c6dc68c478bc97b770aed804f12e1eaea57a368224f62422c921a0ee497722c134a82b05c9c8952786f886f57bb598552a6b61f96929dddd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56960);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_name(english:"Adobe AIR for Mac Installed");
  script_summary(english:"Gets AIR version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host contains a runtime environment.");
  script_set_attribute(attribute:"description", value:
"Adobe AIR for Mac is installed on the remote host. It is a browser-
independent runtime environment that supports HTML, JavaScript, and
Flash code and provides for Rich Internet Applications (RIAs).");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/air.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

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


path = '/Library/Frameworks/Adobe AIR.framework';
plist = path + '/Versions/Current/Resources/Info.plist';
cmd =
  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (isnull(version)) exit(0, "Adobe AIR is not installed.");
if (version !~ "^[0-9]") exit(1, "Failed to get the version - '" + version + "'.");

set_kb_item(name:"MacOSX/Adobe_AIR/Path", value:path);
set_kb_item(name:"MacOSX/Adobe_AIR/Version", value:version);

register_install(
  app_name:"Adobe AIR",
  path:path,
  version:version,
  cpe:"cpe:/a:adobe:air");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
