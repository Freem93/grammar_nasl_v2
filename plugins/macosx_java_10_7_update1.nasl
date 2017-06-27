#TRUSTED 59b22544afc977dd1a80b3d55dee5f5826f8c08db99415cf886283a382611bf93d015c9c76ac78782d760021f34a35c6f0d17d9118d3829284ca6ceb4b6c5213115adb7ba5a12d5c53afa6f30c6757ae0c6154a353a9198c3fafa8ef79123b9aedef0316febeafbe06fe36c29ef3f100bfcb57da38318b8c525889569867597358b82507bf63ed050894078fc9e1dadc1ce0a94313b2f8414d8fbcf85f29b28879ceea1a1b6091bd925bdba9a23036d14c99b995c4f7121be60d8f0fc03b345c623bc33206331bff098d0dadcdbc5f08809df76a545d9620c628051c3270d21b2a9fadd3c5ad7526b77ca09b39b0333499289be91fa6d9ff6a9776a7fde6e39d3d69b76b366c40dd6d28b9af960aac2bda2f1ffb317cb2b87a2671e06ff282596456ab498500568cdb24e59b2c3cc776412c97ebf6dccabdf86ed5c2be444a2607ce36cb4c178fe9ce323892299df50870a88f4d3322ae2ee249fe182857cccc499d266a412b155801bd5880acc5113455848c66a4bfa3d72c0050a30d792ba6ce1fa3a331a6b8fd131c8bc3b9e0cf47928fe133f4d225106e47f38ba133a973ed7e0b30998f838ace24f3cc00c7959140a326eaa723fa933019d051e0d768fea074a40d4ff83aa950b3c8c058534f5f7438330d0a21fd9d5b145df18684a0c67e726a19490c500ca007b91f1c663394ed6f3a027db520285271f0810dc5b9bb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56749);
  script_version("1.12");
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.7 Update 1 (BEAST)");
  script_summary(english:"Checks the version of the JavaVM framework.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.7 that is missing Update 1, which updates the Java version to
1.6.0_29. It is, therefore, affected by multiple security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5045");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/520435/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.7 Update 1, which includes version
14.1.0 of the JavaVM Framework.");
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
if (!ereg(pattern:"Mac OS X 10\.7([^0-9]|$)", string:os))
  exit(0, "The host is running "+os+" and therefore is not affected.");

cmd = 'ls /System/Library/Java';
ls = exec_cmd(cmd:cmd);
if ( 'JavaVirtualMachines' >!< ls ) exit(0, "Java is not installed on the remote host");

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

fixed_version = "14.1.0";
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
else exit(0, "The host is not affected since it is running Mac OS X 10.7 and has JavaVM Framework version "+version+".");
