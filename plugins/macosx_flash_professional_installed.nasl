#TRUSTED 686034fce6aac5c0fd068f985c40514fb3d66ddfaa5085d104aa8b838482731aa906fc1186d9372ccf63644459ea260b29b1cb74cb703688932a77c2f386f9415c7af6f5caf61ae4dbf3179696f363099c2e7c34533d61927bf983c9436283099cbbe69f2ca9aa61c574622ba53b80bb6095aabf9c54de626ccc07eb5036bdf4ca2ef0c61cbf4ea74d913b241da6a56887dafc2c5549be63251aee55ca83773cf680d256a50cacad6a41447ce6a500c3b5ee6229ab3fc90b83c84c84c9f0679f4ee7abeb3537bd4fef357434cf313eb7ec3adad631722626bd2a936a828b44ab06df6bf9327d1b94b6e1670bb1a3ab04cf18998f169eab95d4f1ee5ec87daa9b5f8bc25ec93e404a5555ee437a3a26037da68ec71f02c55d2132a56a39799625f0f3a3e02d684f4d16cf7d31a9c7cfb600e12a4a3930590e5052a1e01e675f785f279e3ed49994199a05303689651a0a63df325fbac04a0081a7657e74cfefcf4b56c86e0c3f4e5709d6930df1e9d63d6561e1781d0b48f3b036ce577cd354e0c222ff4c6b51c1d353e12a93fa852f9cbd1bce46c2aad79ff1cb1b385b37742dcf8c6e0544b8d74fabd69bd3f69ebfff9864df396a2a4094f49d6a1b7a7f5ca3f7a6d3689647e2275c8cec09454310c61967e2f9a0e0d9feb76aee052cbbf2dd77d1ce9fd95c9de3ff2603acba68d04672f12490700fb4020de125cbc592e656
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(59177);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/15");

  script_name(english:"Adobe Flash Professional for Mac Installed");
  script_summary(english:"Gets Adobe Flash Professional version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host contains a multimedia authoring application.");
  script_set_attribute(attribute:"description", value:
"Adobe Flash Professional for Mac, a multimedia authoring application,
is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/flash.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_cs");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

global_var debug_level;

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('ssh_func.inc');
include('macosx_func.inc');
include("install_func.inc");

if (!get_kb_item('Host/local_checks_enabled')) exit(0, 'Local checks are not enabled.');
packages = get_kb_item_or_exit('Host/MacOSX/packages');
kb_base = 'MacOSX/Adobe Flash Professional';

# Get a list of install directories, given that multiple versions can be installed
cmd = 'find /Applications -name \'Adobe Flash CS*\' -mindepth 1 -maxdepth 1 -type d';
dirs = exec_cmd(cmd:cmd);
if (isnull(dirs)) audit(AUDIT_NOT_INST, 'Adobe Flash Professional');

info = '';
foreach dir (split(dirs, keep:FALSE))
{
  base_dir = (dir - '/Applications') + '.app';

  plist = dir + base_dir + '/Contents/Info.plist';

  cmd =
    'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*<string>\\(.*\\)<\\/string>.*/\\1/g\'';
  version = exec_cmd(cmd:cmd);
  if (isnull(version) || version !~ '^[0-9\\.]+') version = 'n/a';

  if (!isnull(version) && version =~ '^[0-9\\.]+')
  {
    info +=
      '\n  Path    : ' + dir +
      '\n  Version : ' + version + '\n';

    set_kb_item(name:kb_base+base_dir+'/Version', value:version);
  }

  register_install(
    app_name:'Adobe Flash Professional',
    path:dir,
    version:version,
    cpe:"cpe:/a:adobe:flash");
}

if (info)
{
  set_kb_item(name:kb_base + '/Installed', value:TRUE);

  if (report_verbosity > 0) security_note(port:0, extra:info);
  else security_note(0);
}
else exit(1, 'Failed to extract the installed version of Adobe Flash Professional.');
