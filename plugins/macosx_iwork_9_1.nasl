#TRUSTED a8a8c0692562b2696d191b7270d2d178e83958f852317868d257a470e6b9abfd87bdbf6043f11eae52ec78b7eaf7207d4e077012dcac05c408c380fcd7b67f26db36967652ced0ae0f8858733163b82d39cb99797de7a9a6e4133a88ceacd822107317d4744463f297ab9dfa88b8e41dbad7b2da35aaebd585f4f2017b2f71d711f277b7b101e86a7211388d9e60409889b397b341003f2e39a7a69b5d412b3106267ca476033f964c5652832685380f1fc86ee93fc64d89037ec09aac8385872fcc82edfc5169e37ccdcee8996b21088e1b01bafb5cb80e8a68ced6f5e3dac988e7fa7bc879ac789f32bd81e159333eaa82bb044c04220cf8a1697805147bd6f87697a682e6081f0cc2c5ac4e2d594ef04ef4a0b7f8c8b1b480acee2b9f5755a0db1c7b0ccb32715490a96989a4be4dbf55a1140136209d8b592a154691b63a6c2a1614ba1cd27566a2ae629851818d5cf7eabade556694afaf87e512c61282c935f331f0ef8263c7de78a74d464852ad4bc26a8997ced71ced68cfb6457e31b1e68636732f6544f01c34359368ccbe15a7160215582ea9950188ea715c28e8283e3a21c32aa6af1131d631955f9a7e3fb73411a7baba211e76af15f2136d74917798736bd126386e75d11184862d0627e39847047b8d958700f14a9554941f769220f2f80513f00a1e82871c10dcae840f5d73e696438efa9c49f490a69019
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(55693);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2012/04/18");

  script_cve_id("CVE-2010-3785", "CVE-2010-3786", "CVE-2011-1417");
  script_bugtraq_id(44799, 44812, 46832);
  script_osvdb_id(69311, 69312, 71479);

  script_name(english:"Mac OS X : iWork 9.x < 9.1 Multiple Vulnerabilities");
  script_summary(english:"Check the installed version of Numbers");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an office suite that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of iWork 9.x installed on the remote Mac OS X host is
earlier than 9.1. As such, it is potentially affected by several
vulnerabilities :

  - A buffer overflow in iWork's handling of Excel files in
    Numbers may lead to an application crash or arbitrary 
    code execution. (CVE-2010-3785)

  - A memory corruption issue in iWork's handling of Excel 
    files in Numbers may lead to an application crash or 
    arbitrary code execution. (CVE-2010-3786)

  - A memory corruption issue in iWork's handling of 
    Microsoft Word files in Pages may lead to an 
    application crash or arbitrary code execution.
    (CVE-2011-1417)"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4830"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2011/Jul/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/518976/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply the iWork 9.1 Update and verify the installed version of 
Numbers is 2.1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages", "Host/MacOSX/packages/boms");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");


os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


# Check list of package to ensure that iWork 9.x is installed.
boms = get_kb_item("Host/MacOSX/packages/boms");
packages = get_kb_item("Host/MacOSX/packages");
if (boms)
{
  if ("pkg.iWork09" >!< boms) exit(0, "iWork 9.x is not installed.");
}
# nb: iWork up to 9.0.5 is available for 10.4 so we need to be sure we
#     identify installs of that. The 9.1 Update does not, though, work on it.
else if (packages)
{
  if (!egrep(pattern:"^iWork ?09", string:packages)) exit(0, "iWork 9.x is not installed.");
}
if (!boms && !packages) exit(1, "Failed to list installed packages / boms.");


# Check for the update or a later one.
if (
  boms &&
  egrep(pattern:"^com\.apple\.pkg\.iWork_9[1-9][0-9]*_Update", string:boms)
) exit(0, "The host has the iWork 9.1 Update or later installed and therefore is not affected.");


# Let's make sure the version of the Numbers app indicates it's affected.
path = '/Applications/iWork \'09/Numbers.app';
plist = path + '/Contents/Info.plist';
cmd =  'cat "' + plist + '" | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(1, "Failed to get the version of Numbers.");

version = chomp(version);
if (!ereg(pattern:"^[0-9]+\.", string:version)) exit(1, "The Numbers version does not appear to be numeric ("+version+").");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 2 && ver[1] < 1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path                         : ' + path + 
      '\n  Installed version of Numbers : ' + version + 
      '\n  Fixed version of Numbers     : 2.1\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host is not affected since Numbers " + version + " is installed.");
