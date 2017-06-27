#TRUSTED 9467a48550f0a6a0ab4cc66e8f28a3c1705d8090d76c1220190728e0963fec3b545afaf6f9340a60efb1505c00cac0c737a2ce3315a5922dcfacf341fa679e9862ca2bc93065ac0a6f2b9707f080f9520138e26b40b7e3d575c3cd1a6655b9976e2e5d99419c10c7b06526b1b917a128a76e29a03a66296991224835e04529ed1aa572f7b82ab92f6d0263d14a2d544d07d28fe311552fa24e133b4f579411dac3b8794966397678b022c044fb01ebfe92314052c20fa9e5e6780e3ddcef312f526691c24ea19b672cb4af8b8cc8fa6c4076db4b32ddf7342bce44045280444449172f379696b7e024ce7c4d7744986342975e2481ad604ac6958ea514a132a9f3e13177e687da7bf3455edabf9225fdec79dd151169bd3c7cc8d56ea71d7899e5640dd557fb0e3995b17cbe2a6f2114fd3314f320d9533245ab5da250814b4701d54f45ed7b4408263fb77cb6a888065fe590e20d1525e8902e99f760bff4f504999f37b99811c48a28419dafac3063edbdf18047378b10e4eac56a84f5c83505a916e7e4f8471e87f7a2d31f96375c6193e6ce57e2eb504304f5f5414cc463f24fbdbed8634bef608e65bee7e7a43b2264371b9d466418a012b8d4f17a44d5547158151494bbcb4e3c12eccc8d90197120ff0b9b8684c82237e1226fea525dd2b9f2f47703dcf18210499fe4b71eb46e98451e6f2525c2774f2a5dee88c2a5
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(58812);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/06/01");

  script_name(english:"Mac OS X OSX/Sabpab Trojan Detection");
  script_summary(english:"Checks for evidence of Sabpab");

  script_set_attribute(attribute:"synopsis", value:"The remote Mac OS X host appears to have been compromised.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus has found evidence that the
remote Mac OS X host has been compromised by a Trojan in the
OSX/Sabpab (alternatively known as OSX/Sabpub) family of Trojans.

OSX/Sabpab is typically installed by means of a malicious Word
document that exploits a stack-based buffer overflow in Word
(CVE-2009-0563). Once installed, it opens a backdoor for a remote
attacker to upload or download files, take screenshots, and run
arbitrary commands.");
  # http://www.sophos.com/en-us/threat-center/threat-analyses/viruses-and-spyware/OSX~Sabpab-A/detailed-analysis.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fbcf878");
  script_set_attribute(attribute:"solution", value:"Restore the system from a known set of good backups.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
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


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


homes = get_users_homes();
if (isnull(homes)) exit(1, "Failed to get list of users' home directories.");

report = "";
foreach user (sort(keys(homes)))
{
  home = homes[user];
  if (home == "/var/empty" || home == "/dev/null") continue;

  cmd1 = strcat('ls "', home, '"/Library/Preferences');
  cmd2 = strcat('ls "', home, '"/Library/LaunchAgents');
  res = exec_cmds(cmds:make_list(cmd1, cmd2));
  if (!isnull(res))
  {
    if (strlen(res[cmd1]) && "com.apple.PubSabAgent.pfile" >< res[cmd1])
      report += '\n  User : ' + user +
                '\n  File : ' +  home + '/Library/Preferences/com.apple.PubSabAgent.plist';

    if (strlen(res[cmd2]) && "com.apple.PubSabAgent.plist" >< res[cmd2])
      report += '\n  User : ' + user +
                '\n  File : ' +  home + '/Library/LaunchAgents/com.apple.PubSabAgent.plist';
  }
}
if (!report) exit(0, "No evidence of OSX/Sabpab was found.");


if (report_verbosity > 0) security_hole(port:0, extra:report);
else security_hole(0);
