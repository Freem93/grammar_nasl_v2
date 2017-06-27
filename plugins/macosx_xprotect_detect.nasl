#TRUSTED 364d2dbc74212a57f621b3430d2c5b13e59a1480108928b6b3157613605476a61580260450cb648b165c8a69330194df6e80e5f6e15a6e3b775b476371990e708add6e6674ef816f43cd64f7cf52025232dedf00d415245311adf70d8cb77d00deef9828d8001665dc49e5fc707a46839d6d009ecd8e2031b823e377e305397e4a716995a06824190d85207705e115c3894bea71a9dfdd6a7342620b354eb350373bdb2a11eb5e10e92a7ec9e98d922ddb62a30499f48264eb83a601359f8ac85d36b5be8204ca06de75f1cda16be45474cb7edfa23babdcb8fabda824dbeb81cca3372a1679661c816a64683475a595224bcdcf53f0ccfdf735988d8493da695423f5ba0df81dda7221f20eb3b589b72fe622b779cbf4b4c2e9877f539abf6a5b2355c451c2248a64fde15f83cb487a7a31da41432f03d6be2b114f0b09eed712e36f121554c214ee761ce312f8a04b366731a120307dc11e4755c9eacadc126b6faaf5da2f1e032ac0bef50c90482e16d45b6cf56ade0d24f2430a9cd4582470165f65d260dfed5fb629aa2e54ab4d710884710397e974229144372c3c7e19ba27b5987d3f52307f5f077d60698aec32b01cb95b958d4c8ec8405a7490df4cecd9ff8d49f05e4b6fb3056a823cc880a675e5f90343cacccd9348d0db3c6906ab5a68e047a69183fea55fecc11cafe1c0b4c810a755f652c005f86efcb361d8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56567);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2011/10/20");

  script_name(english:"Mac OS X XProtect Detection");
  script_summary(english:"Checks for Apple's XProtect");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mac OS X host has an antivirus application installed on
it."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Mac OS X host includes XProtect, an antivirus / anti-
malware application from Apple included with recent releases of Snow
Leopard (10.6) and later.  It is used to scan files that have been
downloaded from the Internet by browsers and other tools. 

Note that this plugin only gathers information about the application
and does not, by itself, perform any security checks or issue a
report."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://en.wikipedia.org/wiki/Xprotect"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
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


# Mac OS X 10.6 and 10.7.
os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");
if (ereg(pattern:"Mac OS X ([0-9]\.|10\.[0-5]([^0-9]|$))", string:os)) 
  exit(0, "The host is running "+os+", which does not have XProtect.");


# Runs various comments to check XProtect's status.
#
# - Is it configured to get updates?
plist1 = "/System/Library/LaunchDaemons/com.apple.xprotectupdater.plist";
cmd1 = 'cat \'' + plist1 + '\'';
# - Does the XProtectUpdater daemon exist?
cmd2 = 'ls -al /usr/libexec/XProtectUpdater';
# - Is the XProtectUpdater daemon loaded?
cmd3 = 'launchctl list';
# - When was it last updated?
plist4 = "/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist";
cmd4 = 
  'cat \'' + plist4 + '\' | ' +
  'grep -A 1 LastModification | ' +
  'tail -n 1 | ' +
  'sed \'s/.*<string>\\(.*\\)<\\/string>.*/\\1/g\'';
# - And what's its version?
cmd5 = 
  'cat \'' + plist4 + '\' | ' +
  'grep -A 1 Version | ' +
  'tail -n 1 | ' +
  'sed \'s/.*<integer>\\([0-9]*\\)<\\/integer>.*/\\1/g\'';

results = exec_cmds(cmds:make_list(cmd1, cmd2, cmd3, cmd4, cmd5));
if (isnull(results)) exit(1, "Unable to determine the status of XProtect.");

if (isnull(results[cmd3]) || !egrep(pattern:"^1[ \t]+.+launchd", string:results[cmd3]))
  exit(1, "'launchctl list' failed, perhaps because it was run as a non-root user.");

set_kb_item(name:"Antivirus/XProtect/installed", value:TRUE);
kb_base = 'MacOSX/XProtect/';

if (
  !isnull(results[cmd1]) && 
  egrep(pattern:"^[ \t]*<string>/usr/libexec/XProtectUpdater</string>", string:results[cmd1]) && 
  egrep(pattern:"^[ \t]*<key>RunAtLoad</key>", string:results[cmd1])
) set_kb_item(name:kb_base+'XProtectUpdater/Configured', value:TRUE);
  
if (
  !isnull(results[cmd2]) &&
  # nb: we're looking here for a file of a non-trivial size.
  egrep(pattern:"^.+rwx.+ root +wheel +[1-9][0-9]+ .+ /", string:results[cmd2])
) set_kb_item(name:kb_base+'XProtectUpdater/Exists', value:TRUE);
  
if (
  !isnull(results[cmd3]) && 
  "com.apple.xprotectupdater" >< results[cmd3]
) set_kb_item(name:kb_base+'XProtectUpdater/Loaded', value:TRUE);

if (!isnull(results[cmd4])) set_kb_item(name:kb_base+'LastModification', value:results[cmd4]);

if (!isnull(results[cmd5])) set_kb_item(name:kb_base+'DefinitionsVersion', value:results[cmd5]);
