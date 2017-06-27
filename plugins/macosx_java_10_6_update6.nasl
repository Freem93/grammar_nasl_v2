#TRUSTED 31141b948127d74c2af6cd07d3094724cb6d7cdfeac6be1af688a19dc11432a6aa35d1e981d87ccdeb9071f8420cf61ef6786da633010c70d94d99b63b0009cd8af86c584bc8c8d510466e002c635e36ce96b1b4537211e4dc434c8771616ef680fdbf155c41bbc5bc931a822146fb03f3212d85bb543d64edfc69499d50eaf20b3b2959c64e8074d95f26acd9e49053a79eb78bc4727308afb398d4aed288e57bfb2c094994097ba517f52d21bbe1212fe8cf413768ace67edaf16a5f80748387d5647a8fec66bb70f27727a785dabe6bac257276041912e14d527a58beeea8b869c7bf33e837cefdf32bb11440cd4dfb908c18217bd36498f525e6132e48913820c78487c4c7ca2bdadf9a1847fbd5c3dfffb2bdbe7f5d9a625d2c1db5905bf8450ae4471590c1d09a87721ae373b6b8f524bc8c0d79e3b545ad3a16544d157413309c9dcbe7cc04a4f072256bb2944b022e99c573deef8bd9678c238ca64913d2d0286ab2c04349747120575ec7c95ef6a64cbd7ce5ca935a95f50de8061f4ddf4a6fba42a52a151ef296748feb155657f9817d32a70782632c68c0ec469ecacb3d7de8dfe5b9f0494dfe56eb0b162fb89ec0f3bc69f3b9fe972a71a6250d786d5492e73ebc919ef96f8703e6340432afef969ccada4939f122a59adc1f376ec0312a36479e5c2debd1a108f06492e9294b2cc8571960e67d5ed456c3a08e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56748);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/10/07");

  script_cve_id(
    "CVE-2011-3389",
    "CVE-2011-3521",
    "CVE-2011-3544",
    "CVE-2011-3545",
    "CVE-2011-3546",
    "CVE-2011-3547",
    "CVE-2011-3548",
    "CVE-2011-3549",
    "CVE-2011-3551",
    "CVE-2011-3552",
    "CVE-2011-3553",
    "CVE-2011-3554",
    "CVE-2011-3556",
    "CVE-2011-3557",
    "CVE-2011-3558",
    "CVE-2011-3560",
    "CVE-2011-3561"
  );
  script_bugtraq_id(
    49778,
    50211,
    50216,
    50218,
    50220,
    50223,
    50224,
    50231,
    50234,
    50236,
    50239,
    50242,
    50243,
    50246,
    50250
  );
  script_osvdb_id(
    74829,
    76495,
    76496,
    76497,
    76498,
    76499,
    76500,
    76501,
    76502,
    76505,
    76506,
    76507,
    76509,
    76510,
    76511,
    76512,
    76513
  );
  script_xref(name:"EDB-ID", value:"18171");
  script_xref(name:"CERT", value:"864643");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 6 (BEAST)");
  script_summary(english:"Checks version of the JavaVM framework.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.6 that is missing Update 6, which updates the Java version to
1.6.0_29. It is, therefore, affected by multiple security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5045");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/520435/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.6 Update 6, which includes version
13.6.0 of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Rhino Script Engine Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

fixed_version = "13.6.0";
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
