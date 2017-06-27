#TRUSTED 659f514898712dc040dbbbf9cd2237d86605d4167370b3868806bb0251b69d7e14f6157030d64be292ccfac9109367da40d7ddb866a287199ed1610447b1ba6364c143a336fde0c779fc35126b60d44035895f8ab9a1ad0445fa77c4f38892b291559c375f042068ce0fd6e9a3097e1fd579bb206388b52d9eebb71e3fa81cdd673356fbe729552bb9729e7eac51251bb868ff5c8f85ba80f431220b2e0a5e4b80f6d00f2517ae5f09504344a1e942a546b178d7485b20d9157f3be2ca101991d30b28ded9bbe4ff868bfe3b168598fbc8cfa5a9c3c91204abd4d58a640a23a01e4ce4d2685f5f2c63f55b8d71ac0afdf126b60d3a31fa53e950ee3625549c80eecaa1597df9b21aba2570d2d929e304fbe74648fc39c72fcb600b09c4e829b45d5c95fe3760aee8312484f822754fab1c50bbaab1ba78646fabd8881694c045303e377130e6775892960686870e76bcf7638f214f9528563538fc4b69757a0ebd4f843a93165169bf157e50bd92cc1ea1262672f55880a5af4ab5157c8034bb0d1f3e2b183dcd0f5cb28eba8294e50501373188c247c4ddc19df6579cd3ce2952660c9b97c3d8cdfa5a517ede2c85afbc8ca979ebbac788515d259c3d0de4e11476602f076910976026564a057a32f0ebe7b49f3a5612272520dd6c53109af0c4d9a03ed8b8ba67071e9dc416039c7fa26c92826c389af9cae0e03b3412bf04
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43003);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id(
    "CVE-2009-2843",
    "CVE-2009-3728",
    "CVE-2009-3865",
    "CVE-2009-3866",
    "CVE-2009-3867",
    "CVE-2009-3868",
    "CVE-2009-3869",
    "CVE-2009-3871",
    "CVE-2009-3872",
    "CVE-2009-3873",
    "CVE-2009-3874",
    "CVE-2009-3875",
    "CVE-2009-3877",
    "CVE-2009-3884"
  );
  script_bugtraq_id(36881, 37206);
  script_osvdb_id(
    59706,
    59707,
    59708,
    59709,
    59710,
    59711,
    59712,
    59713,
    59714,
    59716,
    59717,
    59918,
    59920,
    61212
  );

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 1");
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
10.6 that is missing Update 1.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
to obtain elevated privileges and lead to execution of arbitrary code
with the privileges of the current user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2009/Dec/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/18434"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.6 Update 1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

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
cmd = string(
  "cat ", plist, " | ",
  "grep -A 1 CFBundleVersion | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 13.1.0.
if (
  ver[0] < 13 ||
  (ver[0] == 13 && ver[1] < 1)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 13.1.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
