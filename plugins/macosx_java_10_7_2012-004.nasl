#TRUSTED b053979dbecf91bc4059e35ee195f68459ed885a4214f2837cfc0f96ad0efb94b7ce28f46476eab659156546bf73518a0aa9c260c1f137dc12af190e4814ca522912b50d8e9fee6ceadbaedc1b51fd9cc6b01c86c7034423b7f8ad5322dc745647e762c6d8e2ba9bd7edbf9c84e500338e4f855a4874beb36c6ea463fb1cffb7b07e6cb37ac7f11b272764f23ef8119217244375ce20a5c09a306524bfa0d062fdcc9a1979f45168b6604fd50310693647292c4a651ad6c4e297686a5ca4d6ab6246a696ae8b1f25a71ff9da1293b7c74206cba132ecbb38dca44c1e507578a29f7ac37f87d49ac8dae2b949eea75b4a466f3070842d27d1b8360821c54d7b5c95338eb7468b0c6b22f20d24d447e292f0310d22045b428050c7e321ba602aecbb334d4b5053e639063b95af3fec14cc20971f2a202a30830148d3bf41f53fcf159d3bfd461c4ab59737cef4587f40aae45995d949bd6a5073986fe807cc7a287fd481cec0791d434db943480725371a32d92f5197d3fa0719f2dd083f51af9c668960ca0d13b3c5327a7186f478f2294ae15807b17c3f2ed89edb6b638fda88d9083f297c88461553bda7132ae38c31311c53b8fcac1375aab5b12c74fc3325dae42711d4606bb6e411d13d90b890f49820ffa979ec7e4fe52ebf5cb628190dfdce8f707360f91796f0f8a000fbccd2c46ca4c1cc43d518c13580d465ffc76e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59464);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/11/14");

  script_cve_id(
    "CVE-2012-0551",
    "CVE-2012-1711",
    "CVE-2012-1713",
    "CVE-2012-1716",
    "CVE-2012-1718",
    "CVE-2012-1719",
    "CVE-2012-1721",
    "CVE-2012-1722",
    "CVE-2012-1723",
    "CVE-2012-1724",
    "CVE-2012-1725"
  );
  script_bugtraq_id(
    53136,
    53946,
    53947,
    53949,
    53950,
    53951,
    53953,
    53954,
    53958,
    53959,
    53960
  );
  script_osvdb_id(
    82874,
    82875,
    82876,
    82877,
    82878,
    82879,
    82880,
    82882,
    82883,
    82884
  );
  script_name(english:"Mac OS X : Java for OS X 2012-004");
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
"The remote Mac OS X 10.7 host is running a version of Java for Mac
OS X that is missing update 2012-004, which updates the Java version
to 1.6.0_33.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.

In addition, the Java browser plugin and Java Web Start are
deactivated if they remain unused for 35 days or do not meet the
criteria for minimum safe version."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2012/Jun/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT5319"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for OS X Lion 2012-004, which includes version
14.3.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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
results = exec_cmd(cmd:cmd);
if (isnull(results)) exit(1, "Unable to determine if the Java runtime is installed.");

if ('JavaVirtualMachines' >!< results) exit(0, "The Java runtime is not installed on the remote host.");


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

fixed_version = "14.3.0";
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
