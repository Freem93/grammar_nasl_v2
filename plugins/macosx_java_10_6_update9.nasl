#TRUSTED 2e2c931cb2324b315826f1c8a7dc531b1c4e625b985a97aaa512c5c7618d4ef358a2b7067d040fc19fe6add2df4d7ad2b476cc859c70bd61ffc754d4bcb8122942be605bd977f259422dc9a02032349231f0f92dcf455efe387b5d6123bbd78d1cc3203184c885ab8d9b92d37edb939cfb81c5d275ce7529924f3f4559259fdbd937d0c903f65b80a91a612ec4f78109828af0d0d026e52b6072cf1c8788aee7b334ff0d7b929db968a4d6ac663dcae968ec9f7788b580ab9431cb932b34f103b61c049f70b56c0a3d2621523c699a50798cd39ff373d4fb5ccd8249b8ad016354e3c3729daecc5d56799f6d0b66a4ca2771ce7886c952b0ab936c48a05f3a08396aa858160c6f7f277da5cc9298a77c971bc1e213519f0ea51ec673d456c0089d8b6c928f9eb7079c32c3961134fe6b73fbc23e1d7bdab080a1dce1f47283b2c13b429233efaaf8992e754073ac845a4417d905b0162e3e89ad7ccf684f877ea7c82718059e549fd3d292ef33af4a5a11adbed95e7391a388656ad9ede64eac466bc9859d1a7c91e6a73d1cf2c218ff1b79acad8d2346f9fa4dd82696ae00f9a224b9138893e2b16898b3ca0d8bdd43d6ce53d691d8800c3dc7a1c5d3e3df4b0e6c544cf730886b70d5f6fd904d749d78b6f390fc0e297d60cc7c44a3f271c9d1f24fc7b4facc3f1ee2d0ef4fa3292f68573c5ec2e0cfce1247f77c151c7ef5
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59463);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/11/14");

  script_cve_id(
    "CVE-2012-0551",
    "CVE-2012-1711",
    "CVE-2012-1713",
    "CVE-2012-1716",
    "CVE-2012-1718",
    "CVE-2012-1719",
    "CVE-2012-1721",
    "CVE-2012-1722",
    "CVE-2012-1723",
    "CVE-2012-1724",
    "CVE-2012-1725"
  );
  script_bugtraq_id(
    53136,
    53946,
    53947,
    53949,
    53950,
    53951,
    53953,
    53954,
    53958,
    53959,
    53960
  );
  script_osvdb_id(
    82874,
    82875,
    82876,
    82877,
    82878,
    82879,
    82880,
    82882,
    82883,
    82884
  );
  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 9");
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
10.6 that is missing Update 9, which updates the Java version to
1.6.0_33.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.

In addition, the Java browser plugin and Java Web Start are
deactivated if they remain unused for 35 days or do not meet the
criteria for minimum safe version."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2012/Jun/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT5319"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 9, which includes version
13.8.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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

fixed_version = "13.8.0";
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
