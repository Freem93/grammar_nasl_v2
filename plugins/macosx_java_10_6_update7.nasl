#TRUSTED 030b6f83cce11fb4c015659acb58842dbe39d35097b3d3753521d3d39be25d624377f570435895e8594bd358c723cf35cc7532a0148ba98d8e2e329c1f6dd98a8fc4a6960f81c3a39f93dab5a5c317ee13dd86f5a6aa31b795f0e5b242903c5f0c89b90cf2ce1e0eb3d5d9c4443f73de4a66623e81e4402f3da0015accf194e8ca7e3e2752c6ffa65812568bcff323ed0bc16f4acb38f5f5b5ea0876514732bb7a4b8ed041585fbb770a14dba0464fc98a9528ae55c966e1e835e34c4faf41b9a6efa15b629bcb0e99200ad4a9787b5ecf4fa91744f37b7ad6b62f7c439dded7ee35477e8ba48c53fd2e0489bb7c9139614a9ce2ea1dccecc698b254773abc82d2ab6c44daa1c98d369ad345444733c78d9f65bc4325568c0da2113375b08e191a717278fc1b3cddf47a3addcfbe6470a200e0b6b684a6e58a1d20c8d3af51f6a01826c3becb35801818f568bffbc809ad6ad7cb073a574579b0df742f51c3ef83716ebfebeaddf77c55bc5b4a8fe5b1892536cae0f050a502cd1ca7a8ba7e4d3fccaa800f07feece3a6a3ffb429340e28374689531a3b86a1f6f4eff551b6611fc991e5270106247080a60e3b2e9f6a3c4af5fe5acba6e5aa94bc6e4aa2979792facfc2d1594b68b069e9688b2f1174abaa8942cb123cd3f65e9caf017552e8c7866830ff07e21ed56d7950e12c9c44a5c9607fae9c55eefee64e3475d1a5d3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58605);
  script_version("1.12");
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 7");
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
10.6 that is missing Update 7, which updates the Java version to
1.6.0_31.  As such, it is affected by several security
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
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 7, which includes version
13.7.0 of the JavaVM Framework."
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
if (!ereg(pattern:"Mac OS X 10\.6([^0-9]|$)", string:os))
  exit(0, "The host is running "+os+" and therefore is not affected.");

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

fixed_version = "13.7.0";
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
else exit(0, "The host is not affected since it is running Mac OS X 10.6 and has JavaVM Framework version "+version+".");
