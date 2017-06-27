#TRUSTED 7fc5befcfe9fd99678c4bd961faecf5eeeb9f84a27649276489d075caa81e6cecbc02712d753632a3778b694d89d0f232d715eb2c4b462719a1a039f73f6402ccedc695537da5734312f0bba53b44b4c31a93ef912bdab1558ec04e8cd38edb460e3c6fabe85d415fb357a91c5f3f5cd85c98c6785df081b9a6ac95aa5fc6018efd984a9f7bcbe6787c686bc2fbfea025cf8d70744c904fd858b995a824ccf444808561e1a2cd89466e98c56e44e1554a7963e9cc03b243be0beaeb50279302672e7a6270738a1c5ec81bacd193c8769b63d0996372010d92bbbe68efebf191f0583217d152a91c3dd888aed2523aaf5a2930da760d5d743026562203bdd534f0ba80456ef01bdee96865e841a5bd33e0e770474af1cdd9e639931e99f26009a3bb1de1d0e7fcf1972e73b0cf9a433beaf723f092c47d66757dd1d29c402b1c513d4665912e96a9ccee4362698f715847e52855ea46b217f2db889acefd3ce0ef773973dabb2404e5331e601c076688db639547c4c4cd1587e6b2db0abe6845a10af26a75906e341628c28ed6e454d09d0c7284dbe1f9113b1143e744baa20ae821d827533a88e851351e1b1d8ea302fb4a0351b3b9745a139b2f162c7bc15f79e2bd7d612a966c2f4705726657b15061eae515dd12ca39f2b6e979421644b9d3d13143f6a3f5288cb65d6ef661ff263b8c827df745a492c3e428cc4093c4861
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56196);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/15");

  script_name(english:"Bitcoin Installed (Mac OS X)");
  script_summary(english:"Gets Bitcoin version from Info.plist");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host contains a digital currency application.");
  script_set_attribute(attribute:"description", value:
"Bitcoin is installed on the remote Mac OS X host. It is an open
source, peer-to-peer digital currency.");
  script_set_attribute(attribute:"see_also", value:"http://www.bitcoin.org/");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

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


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


kb_base = "MacOSX/Bitcoin";


# Identify possible installs.
#
# - look under "/Applications".
paths = make_list("/Applications/Bitcoin.app");

# - look for running processes.
cmd = 'ps -o command -ax';
ps = exec_cmd(cmd:cmd);

if (strlen(ps))
{
  foreach line (split(ps, keep:FALSE))
  {
    match = eregmatch(pattern:"^([^ ]+/Bitcoin\.app)/Contents/MacOS/bitcoin", string:line);
    if (match)
    {
      path = match[1];
      # nb: ignore instances under "/Applications".
      if ("/Applications/Bitcoin.app" >!< path) paths = make_list(paths, path);
    }
  }
}


# And now the actual installs.
report = '';

foreach path (paths)
{
  plist = path + '/Contents/Info.plist';
  cmd = 'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
  version = exec_cmd(cmd:cmd);

  if (strlen(version))
  {
    if (version !~ "^[0-9]") exit(1, "The Bitcoin version under '"+path+"' does not look valid (" + version + ").");

    set_kb_item(name:kb_base+"/"+path, value:version);
    report +=
      '\n  Path    : ' + path +
      '\n  Version : ' + version + '\n';

    register_install(
      app_name:"Bitcoin",
      path:path,
      version:version);
  }
}

if (!report) exit(0, "Bitcoin is not installed or running.");


# Report findings.
set_kb_item(name:kb_base+"/Installed", value:TRUE);
if (report_verbosity > 0) security_note(port:0, extra:report);
else security_note(0);
