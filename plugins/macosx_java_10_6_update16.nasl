#TRUSTED aedbb13b8cda92f504b8d6f93efdbc5171d3103b877a04d7fc752d95f430556d65f9cc76350f2b24633b30b19c9793f2308c20bf720c855582d79f4bf35b10f5c0df46f5f213eeeb561799b04f1c1f5dd8fa67e7349bda73681f981355f085374f010d0247f09748f020e582589389296d89b65a0eabf88137f02f45c074cfadebfe07c1b2b73233a691c73967011e831eb9527a7a90f1d3b9a29deec1f9eec4996039250c9972a5f4db05ebea2f9d9f47fd76dd685fe7c835e1528d6a825783b9fc07b3ffdf2497214978867e86700b6aa815c4e6cd25220970afe6c6953016835434acab2ea7792feb2466da76c7f7d2b2af4526fc057fcc84606f410c82d7bf589aec7e2fafd89c726576a4c628797f74902e879a26bd3c3e2702460c50e31b33083e16e88f16cad9bd9ae34b86bbce86af98afcd13ea5da458435b96f7dc75297aa2be5602af1d52b756ffa226b9bdca8ff2d2cee4a87a0cff2eda1fa01ae3a5e14962d8e91e72eb2ac1f90a977db2ea65184fc5eacb5ae0939742d56c5b3e26841bc8f7a688dcdd8d1d22c2d2905321ddb4880c82a9a23c5d08b10ee1dca2f0cf1d3a63086e3465b3d777a7186014989dc0b89088fc24e55d795cce9823f671b32e32a8a55a90fff7fd01f100c79cb0bd1f48ebed759496ab905282ef8706c456915ee1733430d92850c34b71a13bb5edffec1d3aa45af74dccd740154b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66929);
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 16");
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
is missing Update 16, which updates the Java version to 1.6.0_51.  It
is, therefore, affected by multiple security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute
arbitrary code with the privileges of the current user outside the
Java sandbox."
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
"Upgrade to Java for Mac OS X 10.6 Update 16, which includes version
13.9.7 of the JavaVM Framework."
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

fixed_version = "13.9.7";
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
