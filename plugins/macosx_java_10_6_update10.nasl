#TRUSTED 3d39615a66f8731c3bae12311e97dcc7ae3ab919cf0369b85b33a046d09036e1a9c642540464699b6d4d3187cae0d75bc8713c1ccb7c287604755e528f3a6a5c39cac0b094b6723e7028841f7f6687a17ece5c411fc2acae82e27495e54205b730b57844ddadfb511295f253f69c3668086839238941257f0ca8a180d116dcd8b9d18a1f78ff480fad4775f337f26099d7c6cd8f8b6bcc8e5955000ba8f0d49d682c464bbefdbe94b1e0290f3fa485ec8f76600f98c72a5edb5aa3277b998d6c72d9a0be87724fcae46c247d14c6d07a4a4540e232ee0519fecaccd9fa5f1729529c0d455016135afc1337d9dae9afc41d18b17e46fce4b7ca981e72dce9334a4b10aebe827f8f638cc8346d5348258dae747491197ca8c631231e28f9990bbbecf8503e09c41fcfbaee279f2568484a3f22da1441d6ebbf3efd5cfe99833436865940c0ff4ca0f3d83103937b0d8098e779344520dca652a34456c5ab0f33b0c947ffbf7002901cecece5ba84e3cd4c9edb1da55a688d099bee97196f654ea4eefdd254684c777c196c8eb8111419ed1cb924a86dd0687933aef9ecdcf3f42cc62290ed1643ed10b9f4bcec54a6a39297c4f1dc02a8a506cb87aad5d1971b217b73839bfc1d5545bef940169990d9afc1ad395fae72b2bdad97873de1c7b042ab2111b5538d647aa7c81fe7a504d1f8fccf1b44c6b4b5be1c133815e0d58a92
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(61997);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2012/11/02");


  script_cve_id("CVE-2012-0547");
  script_bugtraq_id(55339);
  script_osvdb_id(84980);

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 10");
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
"The remote Mac OS X host is running a version of Java for Mac OS X
10.6 that is missing Update 10, which updates the Java version to
1.6.0_35.  As such, it potentially contains two methods that do not
properly restrict access to information about other classes. 
Specifically, the 'getField' and 'getMethod' methods in the
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
"Upgrade to Java for Mac OS X 10.6 Update 10, which includes version
13.8.3 of the JavaVM Framework."
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

fixed_version = "13.8.3";
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
