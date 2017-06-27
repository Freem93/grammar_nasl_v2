#TRUSTED 6e4b04e1da8030d2fe5347c636c91847421187fdaf7047fd3d2c844287578fcd58faa79e5a354195b4c62e8fa51072080bf8b8e73be8fcc44cc2a945a38f325db325da5a22bf980076121a6d3785167d328fd3e6d736ce176a0800a3c827d00d190da775d16d1813f05288fd95c7cdc6298d1ff09857bc027ab027c5d525f3e84325754c6826f1d8f8716f1d1bbf4f495fd89f140c14210a805ed588326653b41f84c77638e0695df31739b59046b99018e47f537c860802235a394d206e0d042677417200c7faa8b84c9b1dc073385519f96d558807d9bc2e2d417c5dbdfb1da26abebd53fc19d622f124f5851c63db0f6f3306c426ea6d135cdcedfc36f67360ee2372934da09f0b9217fac97efd2e8a73fd707dd8fe78b2c94579d7dd60e7ac093ffc13b7c824a54d60d8015c44cde451b83fd2995112717c6b5a882b10b311d9b6148453d9e58b6970291fff0a9e5a1f56bf3c1feaf144f5a4a7480ce8f58777900e4c157139e85a0ff07350d99b45f969ae2b94d1f070c342b497af9261587efb6798a9cc56e26c71324c105cf6dbdc8b632c7e25dfca9c3e19c91e66ae13161e71c0dbd8c533f1699f81ce07cbeae7c3e86bfd988cbaf3d22a1c2d8484eeae20d70f44018370b60335c3c843fa58d66eeb0f05a5ed0f52361d8500aae3fd4bec668789d4fec203d5e5cf320e8eef8d443cddb129b7e879e06a7a77cb8f
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62595);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/03");

  script_cve_id(
    "CVE-2012-1531",
    "CVE-2012-1532",
    "CVE-2012-1533",
    "CVE-2012-3143",
    "CVE-2012-3159",
    "CVE-2012-3216",
    "CVE-2012-4416",
    "CVE-2012-5068",
    "CVE-2012-5069",
    "CVE-2012-5071",
    "CVE-2012-5072",
    "CVE-2012-5073",
    "CVE-2012-5075",
    "CVE-2012-5077",
    "CVE-2012-5079",
    "CVE-2012-5081",
    "CVE-2012-5083",
    "CVE-2012-5084",
    "CVE-2012-5086",
    "CVE-2012-5089"
  );
  script_bugtraq_id(
    55501,
    56025,
    56033,
    56039,
    56046,
    56051,
    56055,
    56058,
    56059,
    56061,
    56063,
    56065,
    56071,
    56072,
    56075,
    56076,
    56080,
    56081,
    56083
  );
  script_osvdb_id(
    86344,
    86345,
    86346,
    86348,
    86349,
    86351,
    86354,
    86355,
    86357,
    86358,
    86359,
    86361,
    86362,
    86365,
    86366,
    86367,
    86368,
    86369,
    86371,
    86372
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2012-10-16-1");

  script_name(english:"Mac OS X : Java for OS X 2012-006");
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
missing the Java for OS X 2012-006 update, which updates the Java
version to 1.6.0_37.  It is, therefore, affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current user
outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5549");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Oct/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Oct/88");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the Java for OS X 2012-006 update, which includes version
14.5.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Double Quote Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

fixed_version = "14.5.0";
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
