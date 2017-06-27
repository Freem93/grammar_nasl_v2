#TRUSTED ad9ceaef696bd63542be221054027f646698ec6127ab657784d41db5a9beab0fe2c3427a2391607b3595d4fc1887eb367350e3f89805a603f2958fa320b2b7a6ea0c039973b7199775e44f56df8f61491f50536ef8e82ba93863dd0a22d188feb556e37eeca582cce1250e7786b119fafd3bebc349f8bb2fea6a3f65e4817137046dc1d75331cc5e2db1be1de1753eb4953ec4be8406f2c975e3b894dcb55c2faf3d5c05f3aa10c03fc5e519f16be6a3435a06956480b29ccdf4b51424790aea1207f4b6b0b463bcb5550e883884bd9c0d846095414de8406b2423d40cbc8c41f0ea5ed2f11beff0f6a5da78e537bd8815e50eff2d4d0003f44e303f6b231b8ef8e8f199a53f8d686d1477410ad209cf8ffbb1dd2bbd33486465950f5dc55cb67dd2f627bba6a4a379f2aa0291e69de2ba292771d7cc2a382b9a9058c6dae7cf4a63c6f4dc0df2208a0af1a5b9ccfc0e319a3f7d09f4c4a30c3fc9df0ac714269283aed5a33f271ae08fca54bde20db02a9ad66c46305f99f57b8e5e65c85ebcecfc123f1c3bd1ae0be6024c25a2432970d587614e11ad72933d068261ce30318a4aad5174346196274db89a14faf478bf9d1312f574e8a7903788d0fafedcd8310f02d90668a2ee2719befed95ce9780d1ec57206f9cd82d640ea2c0aeebb88be70465660c130264d418189eafe84f157c0c7199f8b5a1c8e76c69e4dbcb8da
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55417);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/08/17");

  script_name(english:"Firefox Installed (Mac OS X)");
  script_summary(english:"Gets the Firefox version from Info.plist.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host contains a web browser.");
  script_set_attribute(attribute:"description", value:
"Mozilla Firefox is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/firefox/new/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:firefox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

kb_base = "MacOSX/Firefox";

esr_ui = '';

path = '/Applications/Firefox.app';
plist = path + '/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, "Firefox");

if (version !~ "^[0-9]") audit(AUDIT_VER_FAIL, "Firefox");

# Check for ESR *before* saving anything
esr_major_versions_pattern = "^(10\.|17\.|24\.|31\.|38\.|45\.|52\.)";
if (version =~ esr_major_versions_pattern)
{
  xul_file = path + '/Contents/MacOS/XUL';
  cmd = 'grep -caie "esr.releasechannel\\|/builds/slave/\\(rel-\\)\\?m-esr[0-9]\\+-" '+xul_file;

  is_esr = exec_cmd(cmd:cmd);

  # is_esr will be any of :
  # 0 - not ESR, no matching lines
  # > 0 - ESR, more than zero matching lines
  # not an integer - ERROR of some sort
  if (strlen(is_esr))
  {
    if (is_esr =~ "[^0-9]") audit(AUDIT_FN_FAIL, "'"+cmd+"'", "a non-numeric value");

    is_esr = int(is_esr);

    if (is_esr > 0)
    {
      set_kb_item(name:kb_base+"/is_esr", value:TRUE);
      esr_ui = ' ESR';
    }
  }
  else audit(AUDIT_FN_FAIL, "'"+cmd+"'", "zero-length output");
}

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Version", value:version);
set_kb_item(name:kb_base+"/Path", value:path);

register_install(
  app_name:"Firefox" + esr_ui,
  path:path,
  version:version,
  cpe:"cpe:/a:mozilla:firefox");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + esr_ui + '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
