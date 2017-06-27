#TRUSTED 781a65c5fbf3763016a22ba7cbcd36f2ff0b2d6df93fcd68a9cd3525aadbc35927ffcca8142c37fec9f2bf21f75fcdf089f831aaa5ddaa3b76015f8c872d72dc8b8d57e5243a4471d64a77f736f51586a385f56de70063b87280ebcebbe53b383a91bde7700c3bd8140998ed38a741c8364bc0d51dac64fb295063034e199e138f487401d318d4f4903ffc16db8815329cceee13a683b383c10f97feb1b0b983f912f358b11e19d4340afd89f626d559e917a874442a1867ecef42db7a196b75ef13b4521e1eb853e631cd79d2aaa0256fa58d47987cdb984805721615d8c5f49fe45654142870b3288132ca36dc753ab17b902c10e629359e118e0815f347d443ac4cbeda0edf6ba8c2a591688008eef66e3dae4674f76860fe7b67d7937ba1cdc95d1ca3bf02a64189210eb46a78706c3ef1ec1b1c2dc787642482be8e7f1a61e50ecb2e4a5e5e2cfe90e237edd848937996e83590b4f645ea8a7ad6708f3aa6db7422fd0517babb8a6d35ce1019081e84fd0cc6c45b2bb4bd08069669c99e9ba8c028df27d49e6c4cdfb6b71fbd5b284d85c0e629e6e71c3706468377c124bcdf9190b3663d236d48365ff73c0324bb7c0b28a8b78bd35b35ec759c1bdca8f95507e7b56648a6b80d159ea424772a6577f58c7ac10ee6ebaa3c8aca356a3ecb61fad866c7bceb18b62878e10e8557375dbb63485e2a6d45178fb9bbd3f2a8
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(64472);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/11/18");

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
    "CVE-2013-1481"
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
    57731
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
    89806
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-02-01-1");
  script_xref(name:"CERT", value:"858729");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 12");
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
is missing Update 12, which updates the Java version to 1.6.0_39.  It
is, therefore, affected by several security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute arbitrary
code with the privileges of the current user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-010/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-011/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-022/");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5647");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Feb/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525549/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 12, which includes version
13.9.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/05");

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

fixed_version = "13.9.0";
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
