#TRUSTED af82ac458c11620a4bad543be2366e283e42d5cec01a1db9f8d5ebfe200db9cb74b0b287a9537f9ebff0a68c1e28125f133a64371f7b571af699343abcc1c0e10e49e371434d632dcf2da2d64cc16cd0acddedb21b80d01e0624f4a0029eb7364a39d7f76af8dcfbcddc7565d7ed5f064ba36295c87e8426a7fe0aa078d96162a7e2e0e2310e7c2b1b3c44ade9b573abcc600e1ea32540a316248b77f2dfb3509203ed78c31e878b2cbe1ff22f8b06edc15ec22ca108993b13bb139881ea798dcbd1f50d12eb842dd98ccc3bebc3f2ef690976b4232af6f88a147d10980caed1d54a2cc4b8ebe706fd48ab95ddf7c314811177ac2dfa4d2b84f5d652b2d36e43b9c5e1d0cec647d769daf56e6885dadc5a3ed0a8704e27074ae7cb494390520cac92f8b007875849fa11c365fe0f0c7300ff0493a2fbd3b6dd4a2d0ae6eff9f42a6bd97c0a7b8d59ecb787205a3de8e398eba6384504f821c6bdf20cb0d206b5acc414dad16520614054fb3ae69a577c19dbf38c3b18aac581ecba5c5f9f6193cdde4dabb6ebc4f44e7c9fef273fb1c6b82c206bb44ba8c8bc8bf92de8b4b7ddbac20ae232add30a5b0724d3f3889afc3972c069eadb591766e26bceb7f6bae4a46ab7c05e167edc539e7d8254ed8255f5dcfbf6fe394c097bf8462100b9b2ebe290cb9767f9338084995ea44941a53ab4f5c2728301a69f8b6808ed54be2592
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43002);
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 6");
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
10.5 that is missing Update 6.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
to obtain elevated privileges and lead to execution of arbitrary code
with the privileges of the current user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2009/Dec/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/18433"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.5 Update 6 or later."
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

# Mac OS X 10.5 only.
if (!egrep(pattern:"Darwin.* 9\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.5 and thus is not affected.");

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

# Fixed in version 12.5.0.
if (
  ver[0] < 12 ||
  (ver[0] == 12 && ver[1] < 5)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.5.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
