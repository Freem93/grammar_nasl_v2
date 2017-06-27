#TRUSTED 185aa0edf53bcd934627fd0a03c91ccbf435b440f0e0d8f9ec3f72caaefc75dca18f1ac88f5b6264a54431d287705058eabf5b267e670bed7d1235e7b8d6a164e6a3a79162dd07804af68e3f08f6201faab851c3c2915b0dae147e00ecc12e4c9fe99790cb6ee2312b015da093c6cf5744f58cdefd2402387d21cb47d82a4090257ec28e7185e26d74a28aa7b213e03e62c9ab6c4bf297fb7c8d982933c709ec7e7f7f9ee5ebd068348773660505e1fe4866a86c62e0f3a4b630b3ce0b19df2979f17fdc7cf4b787fc102658695ebaf43030e76aee2aea259ca3d1916c2090f4c8a71347c7c8a77ae66de9f697612fdb2e42f690658698ed6475cfb7d488a397f45cf3de48693c4bb02ea2f731d34b26c357922171891e16c6ee81d8d2aa0f4f8461619bb1e03a541bc1fb85db8d60d72728f49768a8c148fe03bc5ba6fe9203b493b0a8d2d7c545953ad8f4bbcc5be67d5fceff2b0255d932a7772fd93f3bb5c96d23b4df34253d3c071ec1d1f30282aeddc7340f8cea665b5b2980b28df001d3ef821cbeec6078430802c866659da5ed3dd97e1878903237a61a102d56fed079211e6bbb56eb5c11eb71ae4dcad6c80e15fde61ba544ae083c0f54ac3e61af838424817b3d26b920dc822abc69c18097521a1a22d9be03db61c302ab5b7e8ab2fa9006c54d1a88cf84eeb510b70a94d8fbdcb1c22ef2562b4f1d2b0e51f8de
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50828);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value: "2014/07/11");

  script_name(english:"VMware Fusion Version Detection (Mac OS X)");
  script_summary(english:"Checks the version of VMware Fusion");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host has a copy of VMware Fusion installed.");
  script_set_attribute(attribute:"description", value:
"The remote host is running VMware Fusion, a popular desktop
virtualization software.");
  script_set_attribute(attribute:"solution", value:
"Make sure use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("macosx_func.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("install_func.inc");

appname = "VMware Fusion";
kb_base = "MacOSX/Fusion/";

if (!get_kb_item("Host/local_checks_enabled"))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

path = "/Applications/VMware Fusion.app";
plist = path + "/Contents/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) audit(AUDIT_NOT_INST, appname);

if (version !~ "^[0-9]") exit(1, "The " + appname + " version does not look valid (" + version + ").");

set_kb_item(name:kb_base+"Installed", value:TRUE);
set_kb_item(name:kb_base+"Path", value:path);
set_kb_item(name:kb_base+"Version", value:version);

register_install(
  app_name:appname,
  path:path,
  version:version,
  cpe:"cpe:/a:vmware:fusion");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version +
    '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
