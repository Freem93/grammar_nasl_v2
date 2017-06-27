#TRUSTED 94c8ad62966356ab667f0416e62e3153c309fc46e4f9601668978c61703a2cbde61f0279448ed897859191dc12493b9a7d09e46ea6f30a5f07b6b36206ac0972bbe2fccbaaeb0da852b6fbadfefaa5edee9fbd3084d46f48f6b0a6addf88619c12dbc45af380eea3e6d34af4608e38e836adcb188ec9c30f648d8643ca9735362a9b8116977d98fd4ee635339f82e238429c2fa7a625923ace50a94fbfb94ade4ae16f21d856bcd1a1d5ad8c52964dd53c32ecd8538d2cdffbbb9eeb8c5ee28878d347e38124ff60fc623c7ea10173a2df9007fce091ffa9077b41f1705984a70b653f78e40d011c89d4bbe2761bf13c750223ba7f079a54fca19aae7ae7775d116c737a5fe1a0d7cde715d69f8b59a026f3b095786e6663d97b9f40f507e931e502bc6ef7076c6f47018ffb298da4225cdf709d982ce9e9d5ff83c8c146e7e11f397a9f3fb17a6c9fe8bd5deb8bb03ebc2bc97a38363faa683c612e57c6dcf90bcba382fe5a7a0e969b24ad44989285cc29767ef0001c5937aae8bf7340222da57c856085433c196ebc52226b9bf765c77ca52fa2bf314cda2843d90d2760ee8e3132f0c771e57874d8d1151563b6aa5a2da0247416f0bbad8e5aca9dab0e0e1bcaf474503076a9821190efa9f3edff64c0beaebf67653c9d99f20aa24d8df803e2aa194923ab4ea7d1a6344bc611ec8842482e30ca7f0c7f9c2db7cb5e21c6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66928);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/03");

  script_cve_id(
    "CVE-2013-1500",
    "CVE-2013-1571",
    "CVE-2013-2407",
    "CVE-2013-2412",
    "CVE-2013-2437",
    "CVE-2013-2442",
    "CVE-2013-2443",
    "CVE-2013-2444",
    "CVE-2013-2445",
    "CVE-2013-2446",
    "CVE-2013-2447",
    "CVE-2013-2448",
    "CVE-2013-2450",
    "CVE-2013-2451",
    "CVE-2013-2452",
    "CVE-2013-2453",
    "CVE-2013-2454",
    "CVE-2013-2455",
    "CVE-2013-2456",
    "CVE-2013-2457",
    "CVE-2013-2459",
    "CVE-2013-2461",
    "CVE-2013-2463",
    "CVE-2013-2464",
    "CVE-2013-2465",
    "CVE-2013-2466",
    "CVE-2013-2468",
    "CVE-2013-2469",
    "CVE-2013-2470",
    "CVE-2013-2471",
    "CVE-2013-2472",
    "CVE-2013-2473",
    "CVE-2013-3743"
  );
  script_bugtraq_id(
    60617,
    60618,
    60619,
    60620,
    60623,
    60624,
    60625,
    60626,
    60627,
    60629,
    60631,
    60632,
    60633,
    60634,
    60636,
    60637,
    60638,
    60639,
    60640,
    60641,
    60643,
    60644,
    60645,
    60646,
    60647,
    60650,
    60651,
    60653,
    60655,
    60656,
    60657,
    60658,
    60659
  );
  script_osvdb_id(
    94335,
    94336,
    94337,
    94338,
    94339,
    94340,
    94341,
    94342,
    94343,
    94344,
    94347,
    94348,
    94349,
    94350,
    94352,
    94353,
    94355,
    94356,
    94357,
    94358,
    94359,
    94362,
    94363,
    94364,
    94365,
    94366,
    94367,
    94368,
    94369,
    94370,
    94372,
    94373,
    94374,
    96429,
    96699
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-06-18-1");
  script_xref(name:"CERT", value:"225657");
  script_xref(name:"EDB-ID", value:"27754");
  script_xref(name:"EDB-ID", value:"27943");
  script_xref(name:"EDB-ID", value:"28050");

  script_name(english:"Mac OS X : Java for OS X 2013-004");
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
missing the Java for OS X 2013-004 update, which updates the Java
version to 1.6.0_51.  It is, therefore, affected by multiple security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-132/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-151/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-152/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-153/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-154/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-155/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-156/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-157/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-158/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-159/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-160/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5797");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Jun/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526907/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the Java for OS X 2013-004 update, which includes version 14.8.0
of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java storeImageArray() Invalid Array Indexing Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

fixed_version = "14.8.0";
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
