#TRUSTED 2e8915a8970690a524179f31ab2b93d6dea1ed9adc6c3ea3a9bb7a74b8928df1c74fa55a9d404ab58b8bf188f0b580f3eb014bd27e7445e51016fe3716f920f54ecd56f169da77f635462226441126d81f2b122b5694f21bf009145e230503480ecf2ca1f6be8315e2cc6828c43454978b49ca22f9cbcdd5b5e4c243921e546be9f0a7246c7728ebdb6da48b3c45354a9ef41b4e69124a48356669f2894b4ffc3117502c4622d28c46aacc91be8ce937dd2e60d8799eeb8c1a3ef4f772bd4ad56b9ba8464faa5f0b617b52f74ef20aad34945ada0a662abb6373ae8514a1c5bf82c4d0d534a317bfa947bb1b858ee09a7225b517360853b7ab64f4ecad8d00b3116a5718455239c71c04f1d31771acc10a5ff925c8682443e3aa622b95e7c48af884b1936f8496cb46c8f8759a0ad46fcbba22e4cd908ce2265b56fc541cea96f14bc0d1b15a449c7e19cc04e754551a29fe6149e53f91047b9c1b6f5e106193368a833ecfbbcbb7d3e68a3431c548782e247a885a650576c06a2605d7210b258c805e482d702104852ae103d8dc119b55edeaa7c7f705dd1aa2d96c96894109122acaf2fb8948fd0f0e9e420b4d1dc574cc4b413fb5d35b7a613458d24e2023384054fa85a57fab82a39ffc59cc442c70544860145bcab31090ab5d9c189bc76d3232bffc4943634be7e384f9a2e325a8f557f331b27ad152dae41f66f733e1
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(50072);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2010-1321",
    "CVE-2010-1826",
    "CVE-2010-1827"
  );
  script_bugtraq_id(36935, 40235, 44277, 44279);
  script_osvdb_id(64744, 69032, 69060, 69061);

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 8");
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
10.5 that is missing Update 8.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
or applications to obtain elevated privileges and lead to execution of
arbitrary code with the privileges of the current user outside the
Java sandbox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2010/Oct/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.5 Update 8 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

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

# Mac OS X 10.5 only.
if (!egrep(pattern:"Darwin.* 9\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.5 and thus is not affected.");

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

# Fixed in version 12.7.0.
if (
  ver[0] < 12 ||
  (ver[0] == 12 && ver[1] < 7)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report = 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.7.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
