#TRUSTED 4a6f511afff864f049dd292e4bb8e8768ac67a76a4d1800e264bef346a1b70d0dab8c1bc71813cf536a83a6adcd68f70cc12095fa53b1e36b4ad8387f0531ee3ba91f4abce9dcd3752cbdc73868a223a64e130bf801d49c34ae511e13728df2a8d5e42c5777d12c5530bcda331c61abfab6b89b0fe33fec958b7c0c0ccecd3cee1964e24331f4cfd4a7c1e206b3ad1a7c2cb4208b887ca1b2cb890ba43099e32d3e594c1e2618e3e35a13c578cfc37c5d3207cf80feedba8b4ad976d5ecb66d38bf0fd043bb36941df409dba1b5d6711c848b425d160951824b25238c88c5d62e89d305b75efaac5893fdd9710ec206d0d90854fa95bfea797ebd6332ad61a6ec5a7575938814dea8c268fcb3999b67a837db4f0be246ecc8423840219937a0d52e456669598b799f2711f5673355dccb57db5ef1bc8c641ee642557c042fa568f5b1902128d846881a97811909eec8badcb79035405b342b1d6ba61e2a0d7f26ded563c17b567b77d46feeda7073a48c32b5bbaa992a1166d26aac83f36fad7494c8667aa008cfb779ab5d89bf49e6656a7679fe2f3f5a08c412fdff74f704ecb9320531c3c201562f0fe329e56dda945bcbe683a6a8f22447c720346e7a5d5401b3269e501e2deed5ed0d90d2edbabf1519ed8781db9b9f10bd15adb6463c49f8d35ac1f34506d02664b4a3ac65d4b48e628bcca4278f7a517bec91758822b
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(50073);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2010-1321",
    "CVE-2010-1826",
    "CVE-2010-1827"
  );
  script_bugtraq_id(36935, 40235, 44277, 44279);
  script_osvdb_id(64744, 69032, 69060, 69061);

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 3");
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
10.6 that is missing Update 3.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
or applications to obtain elevated privileges and lead to execution of
arbitrary code with the privileges of the current user outside the
Java sandbox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2010/Oct/msg00000.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.6 Update 3 or later."
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

# Fixed in version 13.3.0.
if (
  ver[0] < 13 ||
  (ver[0] == 13 && ver[1] < 3)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 13.3.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
