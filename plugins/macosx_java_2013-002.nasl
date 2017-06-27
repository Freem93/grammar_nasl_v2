#TRUSTED 36b93a635a7360929a42cad8111d0f192688987ba7cfbee0d9ec5df0d1dc38d5055d2ca0f6e5336f7d7a004b326c815dd9e3ac6d93af8a733a64623c41dc9d49d497db717ccd8eb707e9c67a9ac3c1c901ee860f5e674a5690922c55a5c0b3ff9331f05be5400c1fb6a610610cd9cb54b1718f7206d40ebcb0343f3abb41b24853e25a8872c7eb4919fd75cab36efb65317bbfcf1b3ef4c7ad20a0fffeaf262eecbf6a75b08072817aa6e8504fe188975ac711b56c28fba6c8307f89c76b38f188bb63dcd739de71adfa83575cbc06bb0369daaeae4335c5bdc24d5781d7a05d353581caf6ea5aef7a5862741ab958d69500eeea6dfbb7ac2b89bde6971df15dd2471253b9ee1729819df4e03d19049e66d49d26cc789256c46252ae55b2b6b5d99653ae0d306f0b4948c19f0aed79a00e0fadec8c8a2bb856a0e5e5ca720987ce04c1bc1a66ff2cf4dd81c3351efe7ed7a94a447dea4df14f9c5189f598e02ff135030b7e598ac3e96f9eb3118514fa37e63571e9c015a264c212a12a77da922ffec743882e537c5ef97f70ccdea32f864d3e748a3648ef09c6ebb93901d0da4970314b18575490dff8411ebf6a04096de6e108ab713af240f6370265ea81b62b7a0e70aa91f4770ffd52cf49cbca8cb8be927807954ae15738799080cb1f924b2f68ebde985dbc9d2acab12414046b9fc512dbc782122710cf8b567c640a56
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65028);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/11/14");

  script_cve_id("CVE-2013-0809", "CVE-2013-1493");
  script_bugtraq_id(58238, 58296);
  script_osvdb_id(90737, 90837);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-03-04-1");

  script_name(english:"Mac OS X : Java for OS X 2013-002");
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
missing the Java for OS X 2013-002 update, which updates the Java
version to 1.6.0_43.  It is, therefore, affected by two security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current user
outside the Java sandbox.

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
"Apply the Java for OS X 2013-002 update, which includes version
14.6.1 of the JavaVM Framework."
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

fixed_version = "14.6.1";
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
