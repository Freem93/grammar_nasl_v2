#TRUSTED 13b170114bee6e2d301f33bfee6baf03bf8992f84a286adc01abf4d0f44ef7b06ddcf9701d631844b35915f029a8aae414ea66d85ab4fdeab50ca71e283c31178cf9b9a7a2d859bcbbc11138b7ac735e343502e11aeec2400ec1d7e874e1f6325ea8064de0a977ea75794473e6ca05be7f225633d5ed10da3fcc0fd496d4970a223ed67b15542afd3d59cca5a429c5ed5556afbee117fe5fd9cd0c3bbac650ac6c47441fde15b1ad9a019f000b856833b2300ad3b1a8840be0e7e3c5489fb39515cd540c1ddbb052b2880457ce6f012099830b89dea1cc9c77a3eb51a3916c2b20121409a41621a66d5591ed4f028cd6b6f187df7fdb57289d6bb60fb32248af8a2d1b8adf220faefe6a9a865b721839f657ce2e3714bec553fa6add84f5ca54d94911cd4863f1cdacceecdc6b8c06bbe6893f215fbb75e670a231f3913d215cc7e97730e16c57538559a9ab3f611f62b166b455c3705e331dab7e1f1b12b798172cc85877cad1353c69e02bf6bece1de9698c9be083425bf7e0854a8eb06fdb08ec6107472f5d9fcb592eb61a08a1000e8d4bbbd51a2d1d14e5594c3bf3b94b2d50cdb208d77c4083136310e134c3eabfdde48634fc8334e64b6e4b6487874897d0fea5313407690936bc050541d79ee9af70a5bd4d1f12974c3e383382808dcbf884da54c0d3441bb0dd83c2f8c42afe77834d1ff52a3fc9d3526f5aa3fc2f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52587);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id(
    "CVE-2010-4422",
    "CVE-2010-4447",
    "CVE-2010-4448",
    "CVE-2010-4450",
    "CVE-2010-4454",
    "CVE-2010-4462",
    "CVE-2010-4463",
    "CVE-2010-4465",
    "CVE-2010-4467",
    "CVE-2010-4468",
    "CVE-2010-4469",
    "CVE-2010-4470",
    "CVE-2010-4471",
    "CVE-2010-4472",
    "CVE-2010-4473",
    "CVE-2010-4476"
  );
  script_bugtraq_id(
    46091,
    46386,
    46387,
    46391,
    46393,
    46394,
    46395,
    46397,
    46398,
    46399,
    46400,
    46402,
    46403,
    46404,
    46406,
    46409
  );
  script_osvdb_id(
    70965,
    71605,
    71606,
    71607,
    71608,
    71609,
    71610,
    71611,
    71612,
    71615,
    71616,
    71617,
    71619,
    71620,
    71621,
    71622
  );

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 9");
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
10.5 that is missing Update 9.  As such, it is affected by several
security vulnerabilities, the most serious of which may allow an
untrusted Java applet to execute arbitrary code with the privileges of
the current user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4563");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Mar/msg00002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.5 Update 9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

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
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(0, "The 'Host/MacOSX/packages' KB item is missing.");

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
if (!strlen(version)) exit(1, "Failed to get the version of the JavaVM Framework.");

version = chomp(version);
if (!ereg(pattern:"^[0-9]+\.", string:version)) exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 12.8.0.
if (
  ver[0] < 12 ||
  (ver[0] == 12 && ver[1] < 8)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.8.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
