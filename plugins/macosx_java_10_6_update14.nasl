#TRUSTED a52818f2ae4fba8a104c27567825d08426ea95f3151786cbf4036b8eb4db26aa2357aaeca6b0b471a4699683cba2619d36bd79d33f8f13673cca76b7cd194f1fc47833c1bc6948b3461f9df21f31c5125d7ffb926d30125718124f39d57287c73ac703b683275e92daddaaa401ca20b8ffe238340412307cec2910a7961d7a0f294be0dad69cbc44f83605b1a8501d24d07c60d3816ce043c7c0f3c4daf2b220887034c95ea3efed9ac89198668c83f302def52aafc3d33d42d4749c83aed32deac258d80f70cae3b08f785e9820e38629b3a92ab2deefec692577c7fbd1e55aa1f0b93451b6fac1a4fe852e38f77f1674fdc76e5aa959755604b945fd2af32591502ff21d5b73dcbd6d01c3a17d6bcb03a65ad40fd358cfb569cfb323feb7c4a3643b3382498496d25335352990ab83f1de450b44425d3a5e5d512866dadb567c2bb0f449de9d8ba1d10678a11eeb58acf7212f7ef794717323cbcf0bd77d66dcf2181b7d830b3872d34dae8f1b34b09d6bc5bbd6ad0da76b2bd295d24fecb4482a80758d99950a718c0463ea23254ea836b70fbce4454d50c0c2c476fdf0827a918bdcb35dc541e6a98b7d9c08c6071a867c693f44215ed1e5f5e938f20f7136c0d22c2ea42c46f3accbeb5a3998a4292cef53afa52539139df79d2c4197ff0acf2a1604dab5e63fc6ed54570884705eec32f212ba81b60f499ee9389640df
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65027);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/11/14");

  script_cve_id("CVE-2013-0809", "CVE-2013-1493");
  script_bugtraq_id(58238, 58296);
  script_osvdb_id(90737, 90837);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-03-04-1");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 14");
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
is missing Update 14, which updates the Java version to 1.6.0_43.  It
is, therefore, affected by two security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute arbitrary
code with the privileges of the current user outside the Java sandbox.

Note that an exploit for CVE-2013-1493 has been observed in the wild."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-142/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-148/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-149/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/6u43-relnotes-1915290.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5677");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Mar/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525890/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 14, which includes version
13.9.3 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java CMM Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");

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

fixed_version = "13.9.3";
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
