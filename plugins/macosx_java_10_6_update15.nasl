#TRUSTED 8f0e03b96bd68618987fe91e633fa38d028a9010888c025f4708cb96848018084dd94d238d4fe68a5496ac349f5ec0c12365bf5d4424f60c6a4c6caeacade99d5104103f705ddec7d5d124486aba36758da233f350a347cd3550eddfa4eb59eee304d38a59e99a6c6575e98b4eeb48f1c151c7ed2b5c609c656df51e126cc2c941de66047db392a7b2593f667f6f294323c4d83ba3d72e97c5fe7d8bbdf12c0dd16dcab2efe3652ce7d20a1abf44ba54ee371d20a89a222c173263060e6d238c8e2e64a5420f9450c49e7c33f08085cd7177cc7063d93dbe198e2ce434f087b5638935525bce275b5da8c98ece8cd399431f5fef369d6bf41d2b6b0444fad6526609ce6eec2f45c56b0cb8837569ffe3f9871f2430f32135e29dff2a44ba8c7ba574df046b30a102678cd998ed3a2750a409206b9741604d39fd3235b21b35e5a7cbb88973e0bb5c1ffd1b05945ad6dd1ebedf6d3ab5db6a2309eb18fdd103586e2f5bce3840092375b0e6c94b36834d9ede5e8f16961a7e09ee51b2a8a8bfefbca464dd4a146f47c173b35905e14511fcaad97e0f338d41b77b331c08b67239400a51ea725fd037168751c2f1d5bb791c5eaf2775cff5205dd01deb9c3b05911ca5479b154194dab23bc64504a12a18c25e52b7aa240cb2f02650858dbfd0e5a37c9a3b2cd87ded2fcb58e2ab01ac4b266c55c5b39991561293308bf24b253d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65998);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/12/04");

  script_cve_id(
    "CVE-2013-1491",
    "CVE-2013-1537",
    "CVE-2013-1540",
    "CVE-2013-1557",
    "CVE-2013-1558",
    "CVE-2013-1563",
    "CVE-2013-1569",
    "CVE-2013-2383",
    "CVE-2013-2384",
    "CVE-2013-2394",
    "CVE-2013-2417",
    "CVE-2013-2419",
    "CVE-2013-2420",
    "CVE-2013-2422",
    "CVE-2013-2424",
    "CVE-2013-2429",
    "CVE-2013-2430",
    "CVE-2013-2432",
    "CVE-2013-2435",
    "CVE-2013-2437",
    "CVE-2013-2440"
  );
  script_bugtraq_id(
    58493,
    59089,
    59124,
    59131,
    59154,
    59159,
    59166,
    59167,
    59170,
    59172,
    59179,
    59184,
    59187,
    59190,
    59194,
    59195,
    59208,
    59219,
    59228,
    59243
  );
  script_osvdb_id(
    91204,
    92335,
    92336,
    92337,
    92338,
    92339,
    92340,
    92342,
    92343,
    92344,
    92345,
    92349,
    92350,
    92354,
    92356,
    92360,
    92361,
    92362,
    92363,
    92366,
    94359
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-04-16-2");
  script_xref(name:"EDB-ID", value:"24966");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 15");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host has a version of Java for Mac OS X 10.6 that
is missing Update 15, which updates the Java version to 1.6.0_45.  It
is, therefore, affected by multiple security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute arbitrary
code with the privileges of the current user outside the Java
sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-068/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-069/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-070/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-072/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-073/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-075/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-076/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-078/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/6u45-relnotes-1932876.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5734");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Apr/msg00001.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 15, which includes version
13.9.5 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");
if (!ereg(pattern:"Mac OS X 10\.6([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.6");


plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd =
  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(1, "Failed to get the version of the JavaVM Framework.");

version = chomp(version);
if (!ereg(pattern:"^[0-9]+\.", string:version)) exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

fixed_version = "13.9.5";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "JavaVM Framework", version);
