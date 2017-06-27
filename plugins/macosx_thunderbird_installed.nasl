#TRUSTED ad497339f3f687efeb46892fb7c2b517d3a4245d8ade503aab4106d98577f4b437770cadf682c8e3cab97536567f8f130f6ace245d57193ebf5984922c82622eec7a431f4cc7441c71477fcda58a7e9519a1c513f80576b03c4b295b2fbb164c03f7a1f15763a442978d224971ff90c6d8be149507f8fc265f5e42e43983c65da4e0a593c3a6bd5d7ee8fe8bbea23bd3e9942cb66dd905b9bc101756c781bcbcf991dd9d9d8151258f0ad8b98a9907644c6e476766b07e191383b279e4b8c2f0bdd06f0eb12a3e7359cc08405dcf48cf396b5e3ce1735f0b3f20c6dffaa5716127668e703c54a70430bab450a970e5eac625582cba05d93ae3645d42a602029ee8569a5ee26fb315590fecbeffd70cf3853afec79cff47d6deaed52f01c65345497c9a67c3a2836edd21b0c7606bf68a243bbe32d36ddf65cee3895815ad2c50ce5fba22e6f7835f5fd788a6b3ab277dfb492d4e59abd5986bb141dc6b2932ac678059e4a61b12b56bb3e059a3654b19e576f6e81c7e08e21ffec26f5b9ac0900092169f8a2571ef11e1186db874720330a79905fa2647706536c0c6f5a7fb014c8c33c7cff92340fc69e92bb190403185a2cad74a7abb9798403ffe6dfe08d64e5f74e297b1c145f2f3d95cc3d20ed1da343a8ab8c6e0d2ef50d2b1ffeacf6f9f8a7bb65c701470ae5ceb72c21560efaacddc644880c9b3451353c6992ba72b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56557);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/09/14");

  script_name(english:"Thunderbird Installed (Mac OS X)");
  script_summary(english:"Gets the Thunderbird version from Info.plist.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains an alternative email client.");
  script_set_attribute(attribute:"description", value:
"Mozilla Thunderbird is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/thunderbird/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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


kb_base = "MacOSX/Thunderbird";

path = '/Applications/Thunderbird.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, "Thunderbird");

set_kb_item(name:kb_base+"/Installed", value:TRUE);

if (version !~ "^[0-9]") audit(AUDIT_VER_FAIL, "Thunderbird");
set_kb_item(name:kb_base+"/Version", value:version);

# Set path here so if, in the future, locations
# change on Mac, we can detect and use this variable
# and KB item in version checks.
set_kb_item(name:kb_base+"/Path", value:path);
orig_version = version;

# Check if ESR
esr_major_versions_pattern = "^(17\.)";
if (version =~ esr_major_versions_pattern)
{
  xul_file = path + '/Contents/MacOS/XUL';
  cmd = 'grep -ie "esr.releasechannel" '+xul_file;
  is_esr_res = exec_cmd(cmd:cmd);

  if (strlen(is_esr_res))
  {
    if (is_esr_res =~ "^Binary file.*\/XUL matches")
    {
      is_esr = " ESR";
      set_kb_item(name:kb_base+"/is_esr", value:TRUE);
      version += " ESR";
    }
  }
}

register_install(
  app_name:"Thunderbird"+is_esr,
  path:path,
  version:orig_version,
  cpe:"cpe:/a:mozilla:thunderbird"
);


if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
