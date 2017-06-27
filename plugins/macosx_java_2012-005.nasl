#TRUSTED 17313d02bad1633f970a396956d6dea5c148fa720bf6535bf262a66bafa32ed4e2659902164c0af859dac5fce169e4d4c6c6a68053383b6702ae919595cf5246210c43144568b0e12b28e1b42356966f70ee6d9daaf495c829cad7f4237d9672f0f386d913d23d33a4c34eb54b62f43ad3764f7510bf35646e25f47df8f2b1884c4402e724ce978c07c2edc40ee8a7fca6f452fd122e8287dfc02b5e088709cdac0d066503272ad7238ffe93214ab6f7622db606b6c426ec8228d16529356148be3389c156d7bc98ce594b5f33849ef4087aafd1f28b43cfe331ce643589fc0026b105fabb7cc826638d1adbb346ad89f7c914a3074e5e4bb7bbf2edde7434b6a5e3976a00183629c9012558780074a9045b191ded77e4fac065a574dbd77fb6ec388d81d687e6d4bf0dc2b1c251164df4584dac05de029a095c7c00165210e27659f693acc983a7900b153862ba0e62572da0d990d89df1c68a635868e6880eade9ef58fd3ddf2bc3a7e7e69b10b9399383ce4c90f164f3711e2f2311722a5199c4697955ba30dd9f82f63e8a147277f94e61e2066f7f4140d2b3129acccb2e971be0a541ea9f96f79a5c336a8c1b231ec5f47a8f27b0b85face3b5f84a6b7f7940f75700f438d1598c70d4c07373b14b1a044fac3e9d373694344fcb71404e431cf5b2fc75630c6c5850999ab2f643459ca266270b7bc4582546e72344ca99
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(61998);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2012/11/02");

  script_cve_id("CVE-2012-0547");
  script_bugtraq_id(55339);
  script_osvdb_id(84980);

  script_name(english:"Mac OS X : Java for OS X 2012-005");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of Java that contains methods that can
aid in further attacks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X 10.7 or 10.8 host is running a version of Java
for Mac OS X that is missing update 2012-005, which updates the Java
version to 1.6.0_35.  As such, it potentially contains two methods
that do not properly restrict access to information about other
classes.  Specifically, the 'getField' and 'getMethod' methods in the
'sun.awt.SunToolkit' class provided by the bundled SunToolKit can be
used to obtain any field or method of a class - even private fields
and methods. 

Please note this issue is not directly exploitable, rather it can aid
in attacks against other, directly exploitable vulnerabilities, such
as that found in CVE-2012-4681."
  );
  # http://www.oracle.com/technetwork/topics/security/alert-cve-2012-4681-1835715.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00370937");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5473");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524112/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the Java for OS X 2012-005 update, which includes version 14.4.0
of the JavaVM Framework."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

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

fixed_version = "14.4.0";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "JavaVM Framework", version);
