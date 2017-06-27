#TRUSTED 0efcb169234cf91910b80ecfc9e5de38420f9aa32b905ddfae62fea71f831486fff6b047febb6b7fb79302d9e01cf67463ef15ec2bf0cfdfe7986a406f156474bd93b57d00fc83a02255c8cc3db6c2b85fa786a31023c1ace8f2dc2fe0e620730dddd1c139576302fbc2296589a27275313f4f2a82150d96b6deb1619d7efa3c8caaf6e73a688195b7e4385f2a529cf8c4f9425cec35bcfe5bee797cbf9cbbc09ca6a141d4c03303377722660287d6f6cf24d55eae91353ef7579f70c364bfa9e64521c2a8c3d0f351b2369d7fb5878c44b765916582169f65df0ac5582f521daa0318de80baef6263aea5d3a526f8496d260e82926285661a490b28abce8ba7468dac48d244dc66f3ff138862cf285add544cd6778b9c69384dc101a548d5b6f04f11ffd9ec5981b801d5f03ecfb6dbf7ebff9a3a9a3c915e87ac6519842abf9ce79c787eab34028fd66b821519d2ddccf878e40de8301c5366aef0f8fd670c20a5a9b3cd9493614823e1971d3fe5c350760adaee5623ad8d17d89d3f9e802a560f5cfe9befdc2260723f945768a0f827dc626e9293e08a257025d7481a6d397ed05e95262cac7e3d852f324acf357b167036397f7c27d113b7d186b2f4539776bae5630e381a01cfb7882e236b914d9079ce493ea408a2caa556e92f7d19fae068be3c07e6ca6e51131c0b833cf0f77294df8eef4e13791af34769fadd12b9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64700);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/11/14");

  script_cve_id(
    "CVE-2012-3213",
    "CVE-2012-3342",
    "CVE-2013-0351",
    "CVE-2013-0409",
    "CVE-2013-0419",
    "CVE-2013-0423",
    "CVE-2013-0424",
    "CVE-2013-0425",
    "CVE-2013-0426",
    "CVE-2013-0427",
    "CVE-2013-0428",
    "CVE-2013-0429",
    "CVE-2013-0432",
    "CVE-2013-0433",
    "CVE-2013-0434",
    "CVE-2013-0435",
    "CVE-2013-0438",
    "CVE-2013-0440",
    "CVE-2013-0441",
    "CVE-2013-0442",
    "CVE-2013-0443",
    "CVE-2013-0445",
    "CVE-2013-0446",
    "CVE-2013-0450",
    "CVE-2013-1473",
    "CVE-2013-1475",
    "CVE-2013-1476",
    "CVE-2013-1478",
    "CVE-2013-1480",
    "CVE-2013-1481",
    "CVE-2013-1486",
    "CVE-2013-1487",
    "CVE-2013-1488"
  );
  script_bugtraq_id(
    57686,
    57687,
    57689,
    57691,
    57692,
    57694,
    57696,
    57699,
    57700,
    57702,
    57703,
    57708,
    57709,
    57710,
    57711,
    57712,
    57713,
    57714,
    57715,
    57716,
    57717,
    57718,
    57719,
    57720,
    57724,
    57727,
    57728,
    57729,
    57730,
    57731,
    58029,
    58031
  );
  script_osvdb_id(
    89758,
    89759,
    89760,
    89761,
    89762,
    89763,
    89765,
    89766,
    89767,
    89769,
    89771,
    89772,
    89773,
    89774,
    89786,
    89787,
    89788,
    89790,
    89792,
    89794,
    89795,
    89796,
    89797,
    89798,
    89800,
    89801,
    89802,
    89803,
    89804,
    89806,
    90352,
    90353,
    91472
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-02-19-1");

  script_name(english:"Mac OS X : Java for OS X 2013-001");
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
missing the Java for OS X 2013-001 update, which updates the Java
version to 1.6.0_41.  It is, therefore, affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current user
outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5666");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Feb/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525745/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the Java for OS X 2013-001 update, which includes version
14.6.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Driver Manager Privileged toString() Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");

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

fixed_version = "14.6.0";
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
