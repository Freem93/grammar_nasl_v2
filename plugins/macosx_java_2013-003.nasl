#TRUSTED 0c9b1f2ad1fffb722f1ddba7c4655f10134fecdf65dadf1ad9c56f041cff1e328f2680ed62971c1aca993c9c562b0975b0c09f1bd288ab7cd8bb2115a11a41fd263942af5de974b3ef6b785d5cbce83e612d9a15cb10185f19b137be6e2e6a794edb72ae3210a1ad326155c65b3fa0bb819061910934ae8c36551db9bafe219a3623005a7367ad6fc44435c2836b3a85ba835600393b9e2c4a59db6d0dbcb064f1d3c1fd6531c2373c4ddd76e708a06cd4945d36a66d879e78b2fc6af2c2a9ae24e3f4d830df0984af4a7444e59ee63f17a99a42a6ba9f06a7fe2eff01ad7cc65ed9d4779e130122d49410b85faa33c511efce889f8f57dfd64cf4caaa8ccb7bce6fe83b53e121effe3e06bc6b2508e1b40746cb8b49e29c2a5aac4b334d25d1573ad20297acf681b1febae474a7fdc8b93d937b1fdedf269725aad1bf56b6f4886d656c65f6fbb8fa843ccc7bfdf6b315248268863c1694b49631541ab7ef3f0263b0dcbd3ec5edc8c5940c67e52e49c20ea15b8608662f72c882c96a1bdc505e5f244ce9ef418e2576c44ccee4589136aaff3c38e79cde79a7f3d8197343e13fc64c4bde4d9ac285ebdb5f087557946e3cca416f9c7550a8f5afec15bd1526039be7062f2e221459daf23d978409a78129e2b9027dfb17cbbb8e638f673a9a807329142056a8c95a38845245a3924943a8b7af694f79de94679ddf49a34fdd
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65999);
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

  script_name(english:"Mac OS X : Java for OS X 2013-003");
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
"The remote Mac OS X 10.7 or 10.8 host has a Java runtime that is
missing the Java for OS X 2013-003 update, which updates the Java
version to 1.6.0_45.  It is, therefore, affected by multiple security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current user
outside the Java sandbox."
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
"Apply the Java for OS X 2013-003 update, which includes version 14.7.0
of the JavaVM Framework."
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
if (!ereg(pattern:"Mac OS X 10\.[78]([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.7 / 10.8");

cmd = 'ls /System/Library/Java';
results = exec_cmd(cmd:cmd);
if (isnull(results)) exit(1, "Unable to determine if the Java runtime is installed.");

if ('JavaVirtualMachines' >!< results) audit(AUDIT_NOT_INST, "Java for OS X");


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

fixed_version = "14.7.0";
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
