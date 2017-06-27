#TRUSTED 974420204d810c5712dfb31f1d1dd82178ddf0b7e57b2f31a957f8e798cacc0cfe9656542467860e12fda62ecdaa61aad27ae09bd400f37f7929db0e53e657f06a892edd785336152589dd05d4d48a48f15b0c5fd03d993720f88d15da92107c02b219f3dbf80655e2117692eab7d3db06f702f95898f00da3c547d54c2eeb0b7308c672e1f992b8f01eafe2fa8e1fdeb9bfa818ca615ec143446a55adf22ad001cd3773aa6a2bf280db4fc1e41491d7cef446ee2f8e997193fcc1baa31af4cc76df70ea76bc0b1d7b2534791bbef4669c8c9bf84e28694f2927f44f558bd938f4f412625f2dd3d98a2ce64ebc1705bf6bbb0e95920066b075fd1a9936a0073e3180c32d0ae64c1afb0bc012c440318f2188bfce56a07a99802f1702593feca67fb6b5517c11cdc971e76942a7d30c5b814732735656e2a5dee7b0345ff48068bfe10879c6d25090d07220c4d9cc4218e793159b529240786103c002834fa0a264b78328ef3227126ab99c135e02b9846c1cc73ddcae3509573759968bac9d61f141b32a89a96c8bddd9f74a20cb4e929397f09378b2b5d3b2f90ad5f5ad0347753063780efdd4164f7f9d7385e63c847e50888c2e9cbb05e167685dcf5af042efdd8297242aa1833de9e9b51b6c0570aecca2fb5e10912d844ec5257c5454d531930c68029b5eee77d300d94b07fa7e7d07b28fe0b38a81a109a98038def4c2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46674);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id(
    "CVE-2009-1105",
    "CVE-2009-3555",
    "CVE-2009-3910",
    "CVE-2010-0082",
    "CVE-2010-0084",
    "CVE-2010-0085",
    "CVE-2010-0087",
    "CVE-2010-0088",
    "CVE-2010-0089",
    "CVE-2010-0090",
    "CVE-2010-0091",
    "CVE-2010-0092",
    "CVE-2010-0093",
    "CVE-2010-0094",
    "CVE-2010-0095",
    "CVE-2010-0538",
    "CVE-2010-0539",
    "CVE-2010-0837",
    "CVE-2010-0838",
    "CVE-2010-0840",
    "CVE-2010-0841",
    "CVE-2010-0842",
    "CVE-2010-0843",
    "CVE-2010-0844",
    "CVE-2010-0846",
    "CVE-2010-0847",
    "CVE-2010-0848",
    "CVE-2010-0849",
    "CVE-2010-0886",
    "CVE-2010-0887"
  );
  script_bugtraq_id(34240, 36935, 39069, 39073, 39078, 39492, 40238, 40240);
  script_osvdb_id(
    53176,
    63481,
    63482,
    63483,
    63484,
    63485,
    63486,
    63487,
    63488,
    63489,
    63490,
    63491,
    63492,
    63493,
    63495,
    63496,
    63497,
    63498,
    63500,
    63502,
    63503,
    63504,
    63505,
    63506,
    63798,
    63799,
    64866,
    64867,
    69032
  );

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 2");
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
"The remote Mac OS X host is running a version of Java for Mac OS X
10.6 that is missing Update 2.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
to obtain elevated privileges and lead to execution of arbitrary code
with the privileges of the current user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2010/May/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.6 Update 2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Plugin Command Line Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(310);

script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}


include("ssh_func.inc");
include("macosx_func.inc");


function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(1, "ssh_open_connection() failed.");
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(1, "Failed to get the version - '"+buf+"'.");

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

# Mac OS X 10.6 only.
if (!egrep(pattern:"Darwin.* 10\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.6 and thus is not affected.");

plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd =
  'cat ' + plist + ' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 13.2.0.
if (
  ver[0] < 13 ||
  (ver[0] == 13 && ver[1] < 2)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 13.2.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
