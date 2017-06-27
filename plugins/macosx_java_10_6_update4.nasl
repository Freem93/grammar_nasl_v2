#TRUSTED 93c554674ea1edf8d11f2999ceb435f6d6f2fb39034a92bf40103d43ed931f41f69ee61c7632c5f3941ae6c1bb4054483670719475eb1b07381834b9c7ebec24899adab9be76a59388b6d9fc48103e6d2580160c9dcc0a48bbe7b37fc6798ef72cd2fed4fe9f215686fcad09acc97e3d5dafa4fb22633d44ea2990340953ee06b96018e9c7928320a913cafef3d9ac0f4722059183d902748d7fc35bc7694cb6c5f8563e447ff285ffbfad351a939f88a850125aefaab0cbc6c6b4c08563d0480121e26291a1b2d6b130d0d1a1db27155518e0aeee401d7f675a3797d3f120412946161bd2e60eb1093afc401bbed47dfcc23667d8feaa9a84d8a40532893eed10b7f4c5f4371d618dc784ac4190760fad4fe9cd2e847cbc8711e285200fd9550e06ca1e15c662b3769e7ee1ea14fc9f9ca514e8a58910e135c1651f7f4f4b8754346f00bc4062f8d871b7be3323149824d9ba13c8367e3465f778451c665e32e4695e19ce7e23351559b93ec00a8385d00b636241a4b180c3af4e5280a396538d7f6732fef94208595432a06d00441d55410cf79cba56dccefb83b562a4d2d4b486418059fa456d7cc975835ea3c7aa2d97ed3da3345c4ee74d9e1eae9df5684320f123346778e414ebc13c08d75b3de5109418df9e998d66508c268bbaea685d7b1c0b1a55857af37bf7292086dfcc38071143997239306ee538d0f01f3125
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52588);
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 4");
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
10.6 that is missing Update 4.  As such, it is affected by several
security vulnerabilities, the most serious of which may allow an
untrusted Java applet to execute arbitrary code with the privileges of
the current user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4562");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Mar/msg00001.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Java for Mac OS X 10.6 Update 4 or later.");
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

# Mac OS X 10.6 only.
if (!egrep(pattern:"Darwin.* 10\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.6 and thus is not affected.");

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

# Fixed in version 13.4.0.
if (
  ver[0] < 13 ||
  (ver[0] == 13 && ver[1] < 4)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 13.4.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
