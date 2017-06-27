#TRUSTED 7cae44e077a8e16928141c45f1234fd11489f9392b8d84c66062622ebc59c84c7d0f5bd6a90dc8beb60f37d08ac8f0395c304f6fb82f2fff1564686ebf04fc5774f192dd967239db423591b80d1b0a5263cec099a8b7aca0c736315f5c4ffa31dc1362507a16bcda2d646ae808910c472773024372c96f0c9063b1f68666f4ac1746f4a03263c4b1860333cce7946c1ccad9aeb896d47322b85ff13f9b16ffccc10756bd400cff467aa819c6836ee40c8aa8e3cd87aaace9d5a8feb015e48ade5c2c4f88b4e62848f7e3e5708acae9377d09ddc8af8199c103e3334e931a41805ad9d47b34906fe3ee520cb5911c92084f9b9982b52ce902e307c3f7cb3a7c0a1e83db6da6a0eceec0c115bffacffdfafe36784bb8b25858e44021038c146a30f43be102e993900b2ef2522e5cd60c9f54fa770e561fe220829a4a1697fe314a37918d5379379c705a187a7511177a95799bfa2bdb6db6db2e36ca8d6931d2cb209fda58b40e637e4dd3e1f12d3086ca094531f225e3319e35c412872249b456a9373da54e37c310310e6825b748d2d646bf1c6eb26b3c2d52d68dbe361f71285b9efd2b6a50f4f6892ffcb83955fad8019066df34a98a1c13939e14d355ad30093a8bf672ac1f085cca8161178af85b34515c8bf39fd7b2fd75c3822c3f6246c66accf7bbaff8b2cb4979cf0343d93dd396dc9fab1cf4e7b7104fbc2f0e3b8a
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70458);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/10/22");

  script_cve_id(
    "CVE-2013-3829",
    "CVE-2013-4002",
    "CVE-2013-5772",
    "CVE-2013-5774",
    "CVE-2013-5776",
    "CVE-2013-5778",
    "CVE-2013-5780",
    "CVE-2013-5782",
    "CVE-2013-5783",
    "CVE-2013-5784",
    "CVE-2013-5787",
    "CVE-2013-5789",
    "CVE-2013-5790",
    "CVE-2013-5797",
    "CVE-2013-5801",
    "CVE-2013-5802",
    "CVE-2013-5803",
    "CVE-2013-5804",
    "CVE-2013-5809",
    "CVE-2013-5812",
    "CVE-2013-5814",
    "CVE-2013-5817",
    "CVE-2013-5818",
    "CVE-2013-5819",
    "CVE-2013-5820",
    "CVE-2013-5823",
    "CVE-2013-5824",
    "CVE-2013-5825",
    "CVE-2013-5829",
    "CVE-2013-5830",
    "CVE-2013-5831",
    "CVE-2013-5832",
    "CVE-2013-5840",
    "CVE-2013-5842",
    "CVE-2013-5843",
    "CVE-2013-5848",
    "CVE-2013-5849",
    "CVE-2013-5850"
  );
  script_bugtraq_id(
    61310,
    63082,
    63089,
    63095,
    63098,
    63101,
    63102,
    63103,
    63106,
    63110,
    63115,
    63118,
    63120,
    63121,
    63124,
    63126,
    63128,
    63129,
    63133,
    63134,
    63135,
    63137,
    63139,
    63141,
    63143,
    63146,
    63147,
    63148,
    63149,
    63150,
    63151,
    63152,
    63153,
    63154,
    63155,
    63156,
    63157,
    63158
  );
  script_osvdb_id(
    95418,
    98524,
    98525,
    98526,
    98527,
    98529,
    98530,
    98531,
    98532,
    98533,
    98534,
    98535,
    98544,
    98546,
    98547,
    98548,
    98549,
    98550,
    98551,
    98552,
    98553,
    98554,
    98555,
    98556,
    98557,
    98559,
    98560,
    98561,
    98562,
    98564,
    98565,
    98566,
    98567,
    98568,
    98569,
    98571,
    98572,
    98573
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-15-1");
  script_xref(name:"IAVA", value:"2013-A-0191");

  script_name(english:"Mac OS X : Java for OS X 2013-005");
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
missing the Java for OS X 2013-005 update, which updates the Java
version to 1.6.0_65.  It is, therefore, affected by multiple security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-244/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-245/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-246/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-247/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-248/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5982");
  # http://lists.apple.com/archives/security-announce/2013/Oct/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74a1d7ee");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/529239/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the Java for OS X 2013-005 update, which includes version
14.9.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

fixed_version = "14.9.0";
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
