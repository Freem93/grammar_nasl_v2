#TRUSTED a14550185f77347300bb06c971eca06e3678667bf5ae5cec27b319256679e41b37db20340195b8e60beba5de29836500bfda8aae8b8f119498c8360a1e66e92f3499281e225b234538fed88f275999859456047ddc150c5ad8ba743b26eb29465096f6d4225b8af9698d5d525d14f89066e29122a58bdf94b1a704c63b031c1b7bb05fa4c51c316617b0594a24e04ab39b28eac922a551a7adddcfb893344b2574d5eb8c62dbe7b1e01d8794d10aed44b644c844c76bda7a75416e97c94017dc672607c17c6990dea76cf7e83431364fad244b182f3ee30492bb216d8f375eba81c214f4b5621390f431a258536c195f6ab4b79e3a84e18a0daa4783652584f1c15e8140e4b293cbe5593bc93587b67493a99d872e545003f495d73755994fa70aff6f60b77e955bac6574de3a96242c7cb7ff3e40196f53a315ee1510a0dd4781d150f898642bf5750ec4cb82f1f50ffe293242c83c20bb48355bdcf386e3804efa9ce8e367426cfdc03b130753206f4acab7af69ec14e2f83ea556cb02080cda02d15d4e89422415ceb723482ee108a5254a5ab1d5ebda3040de9c164ea3b76299bb258013f70b675b1afb1de44802350cd03aa489b34f6b72556b4dae4637a1ec2964db4d2f3861efbc16a1affe36d19604fca22c4e512a740890d611f3c6b6cdb3318efaf57da9b326b16b7cf6807f754eb901b535ca30443abce84fcc1b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58606);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/12/14");

  script_cve_id(
    "CVE-2011-3563",
    "CVE-2011-5035",
    "CVE-2012-0497",
    "CVE-2012-0498",
    "CVE-2012-0499",
    "CVE-2012-0500",
    "CVE-2012-0501",
    "CVE-2012-0502",
    "CVE-2012-0503",
    "CVE-2012-0505",
    "CVE-2012-0506",
    "CVE-2012-0507"
  );
  script_bugtraq_id(
    51194,
    52009,
    52011,
    52012,
    52013,
    52014,
    52015,
    52016,
    52017,
    52018,
    52019,
    52161
  );
  script_osvdb_id(
    78114,
    79225,
    79226,
    79227,
    79228,
    79229,
    79230,
    79232,
    79233,
    79235,
    79236,
    80724,
    89190
  );

  script_name(english:"Mac OS X : Java for OS X Lion 2012-001");
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
"The remote Mac OS X host is running a version of Java for Mac OS X
10.7 that is missing update 2012-001, which updates the Java version
to 1.6.0_31.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT5228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2012/Apr/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/java-dev/2012/Apr/msg00022.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for OS X Lion 2012-002, which includes version
14.2.1 of the JavaVM Framework.

Note that these vulnerabilities are actually addressed with Java for
OS X Lion 2012-001.  That update was found to have some non-security
bugs, though, and has been re-released as 2012-002."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"metasploit_name", value:'Java AtomicReferenceArray Type Violation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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
if (!ereg(pattern:"Mac OS X 10\.7([^0-9]|$)", string:os))
  exit(0, "The host is running "+os+" and therefore is not affected.");

cmd = 'ls /System/Library/Java';
results = exec_cmd(cmd:cmd);
if (isnull(results)) exit(1, "Unable to determine if the Java runtime is installed.");

if ('JavaVirtualMachines' >!< results) exit(0, "The Java runtime is not installed on the remote host.");


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

fixed_version = "14.2.0";
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
else exit(0, "The host is not affected since it is running Mac OS X 10.7 and has JavaVM Framework version "+version+".");
