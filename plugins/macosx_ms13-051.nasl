#TRUSTED 9620e217b277fab1a5ab805129fd33a7354511a7c41f461088e3f1be407573babc90934ee5fceb20a678c0b062d0665bcd3c9c488c955c0afeef1b9dbab1f1d7d391c2c69f38e5df422f74b9d45b3850cc5f3167aaa583d25092f04f728fb769edd4dc17017198499bc573609e6bea025923ea2f20b43fe382317de42d65f79f864ca5c362997e72d6b7c5cf39ee05a1dfdc1a63723411604941a38df417811e9d9b31e57e99d09cb226eab53873c1b87f5477ee064ed5cf0fa24e4de78dadbfdeaf728694ebe4ce700c0fe489bdf86d14a05573f1caa40eb9b60995ac4ac14f78081391bb9f42121dee61ae1280574ef3cd48bb941b45b4195fc86e2bb45681d63bacc836342015b0aa4d26f4a1a3297e4c7402132056d72ec0add3bdcb53ca87f1b8df386a3fa4fd7190c77ac8157752c655c61cb6db59bdca94d9698e3b00fc31b966df6c64390255a8570c2be0e753379a751555d04dcb16e3237e350bf341bfc98003b1a239bc591af1ec28867490da8798da304f3278c011ec8e1788ba5a50e38dd5a2e25019c785cd9394311c83ce2570c40a4b7dd81ec344f20eeba7882b2b7bb5827bf280c8dbd8a79739fc21f11e538d7be08095f04a020ca6f15bd776e507a994d10e08474fb1f388c94b19df64fad631ae653f9d16efd4a09777171fdc0f13ef761124a46202d7ac0d4d7835c8057199ce53a3715004c0b7fa10
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66868);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/15");

  script_cve_id("CVE-2013-1331");
  script_bugtraq_id(60408);
  script_osvdb_id(94127);
  script_xref(name:"MSFT", value:"MS13-051");

  script_name(english:"MS13-051: Vulnerability in Microsoft Office Could Allow Remote Code Execution (2839571) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host has a version of Microsoft Office for Mac that
contains a buffer overflow vulnerability because certain Microsoft
Office components for processing PNG files do not properly handle memory
allocation.

If an attacker can trick a user on the affected host into opening a
specially crafted Office file, this issue could be leveraged to execute
arbitrary code subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-051");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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


# Gather version info.
info = '';
installs = make_array();

prod = 'Office for Mac 2011';
plist = "/Applications/Microsoft Office 2011/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^14\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.3.5';
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(fix); i++)
    if ((ver[i] < fix[i]))
    {
      info +=
        '\n  Product           : ' + prod +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Report findings.
if (info)
{
  if (report_verbosity > 0) security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac 2011 is not installed.");
  else
  {
    msg = 'The host has ';
    foreach prod (sort(keys(installs)))
      msg += prod + ' ' + installs[prod] + ' and ';
    msg = substr(msg, 0, strlen(msg)-1-strlen(' and '));

    msg += ' installed and thus is not affected.';

    exit(0, msg);
  }
}
