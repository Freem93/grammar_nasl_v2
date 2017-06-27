#TRUSTED 9386760078163b9dacdfaa002f5478eb9f2816f8589033e9877aa31b2ac9e2cab12df29480825c75eb59b1d66d37a4541f40ef266361b544c0052896f3313d4c1d2059f9c9f247cede67567b655c22418432c5b5c0da17c7d05d3e28d68db4bd4a33f14e6bb36a9ff74bd8427813a574a47eb624767a2d4b639344b47a5d91bc456d8a441a4ed400356ae9f7a8f7c2322eb5cc30d3e6e5419e8c10739df816235813b11f91981afbfd3386503ee037e69da939ae5b188036b4e33c5114efa3897a4d98445b143b9048b327314d9469af6560b42dd8f383f6ec9670bff87a367fa00989005c97993fdc68954134bde0f6abbc551db511347248e66794fc38d8ba896cf6ed252b217a657957c6afbd19a4cda33e13d40f013ed7c2ab36315d681ea99b9a66a78b76e69be7e489573add010a3204dceb343648b25bb846ec21930d6ce51bfe6af6ef2941b77c0712f2341e035527d14f3843bda53fffbff6a889dd9aad5a6eee07ce46eebe420f48191651e9cf3adeb2d7b40c20ee79f682324829fb7508f848856b2bc681af0c3bd9a92b2e539ea19a2e195777d8b9bb9a935936a7f89a199803252311979443ef8f927d52ca93d67efbf6a8ac483d880fe73b5ba7ef51055fd9f15602f927f086e5319b6286c943e31f1a7bf2b8139baffec220dd35387b6b23170efeec928a469274990f09ccd4682b4080b0effa593abd0a15
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78891);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/11/06");

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

  script_name(english:"Mac OS X : Java for OS X 2014-001");
  script_summary(english:"Checks the version of the JavaVM framework.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.7, 10.8, 10.9, or 10.10 host has a Java runtime
that is missing the Java for OS X 2014-001 update, which updates the
Java version to 1.6.0_65. It is, therefore, affected by multiple
security vulnerabilities, the most serious of which may allow an
untrusted Java applet to execute arbitrary code with the privileges of
the current user outside the Java sandbox.

Note that the Java for OS X 2014-001 update installs the same version
of Java 6 included in Java for OS X 2013-005.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6133");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/dl1572");
  script_set_attribute(attribute:"solution", value:
"Apply the Java for OS X 2014-001 update, which includes version 15.0.0
of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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
if (os !~ "Mac OS X 10\.([789]|10)([^0-9]|$)") audit(AUDIT_OS_NOT, "Mac OS X 10.7 / 10.8 / 10.9 / 10.10");

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
if (version !~ "^[0-9.]+$") exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

fixed_version = "15.0.0";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + 
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "JavaVM Framework", version);
