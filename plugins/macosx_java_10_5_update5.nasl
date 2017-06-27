#TRUSTED 745dc6dc924c3565c30fdbbf5372ce93687750392ef22d19a096b7996c041a8c7f59050afb3aed104b9abcbb6ddf81c929d9bc9199227d295ef7b5fa82ea4304c719169893a0c2d96a4148a953f95f8a7368ce92042a099713420abcc676f40a170c56aebdc78ec0cf28cb7264c73041255d45508cd5209599f128f56c5b598bb4a36f39e62c64edf3235e6fd7c27582df72709e6f43cfe351eff499d479f57faf058a80a87cd127b3d59f9eeb73b3bd6f965f4cc22aac69a22516a98d6efa61a8168d8e61cbb251c20a9379e4562a3bfbea82eb904a10b72dab52d3ddb4953213e1e12f332c0a322f5237ee7f2ca7e8b3cdfa4f929922ab896ca7a0f96c12b49617502752fbb4c60e98308c8d2a211d0608553521783d9c2c3ed8daca91f1baa068bab0b624d27c35f44293dc6c7d1fa517f07ea477e838a98993bf2bbb13b2510ae7e0a4d0c9de9b1d0dfd4cf11b1ee8f7c3f56285e8f1a4e5f31c1671f21e7052434719159b42d3ea52172c9534b574c525787e05f5a0c15daa305152ec9bac4184749cda883fc0004ce7814fc320185e4c6b6895a0b0f9be798f0e612843dd987f56b8e2c84780dcdf1126c2249a53b5fcc99f6cb20157be026892c0cccca90c4401a67a2746f0f775fdfdefbe76d3582ebe8ec371e311b4800499e180885e9d5dea3289b312b90b737e00f1b34128c50dd38d1a8b933909454379e744d4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40873);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id(
    "CVE-2009-0217",
    "CVE-2009-2205",
    "CVE-2009-2475",
    "CVE-2009-2476",
    "CVE-2009-2625",
    "CVE-2009-2670",
    "CVE-2009-2671",
    "CVE-2009-2672",
    "CVE-2009-2673",
    "CVE-2009-2674",
    "CVE-2009-2675",
    "CVE-2009-2689",
    "CVE-2009-2690",
    "CVE-2009-2722",
    "CVE-2009-2723"
  );
  script_bugtraq_id(35671, 35939, 35942, 35943, 35958);
  script_osvdb_id(
    56243,
    56783,
    56784,
    56785,
    56786,
    56787,
    56788,
    56956,
    56957,
    56965,
    56966,
    56967,
    56968,
    56984,
    57912
  );

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 5");
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
10.5 that is missing Update 5.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
to obtain elevated privileges and lead to execution of arbitrary code
with the privileges of the current user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2009/Sep/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/17819"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.5 Update 5 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/03");

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
  local_var buf, ret;

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
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");


# Mac OS X 10.5 only.
if (!egrep(pattern:"Darwin.* 9\.", string:uname)) exit(0, "The remote Mac is not affected.");

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

# Fixed in version 12.4.1.
if (
  ver[0] < 12 ||
  (
    ver[0] == 12 &&
    (
      ver[1] < 4 ||
      (ver[1] == 4 && ver[2] < 1)
    )
  )
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.4.1\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
