#TRUSTED 7f020be18eef73eb9baaba2dd42a1f231656bc81e198342d49d3221aabb7a189552463368b3ea0eadf9627ee9ca1b1f0db7d59e9e861a0e5e7dcc879a7f30282af0b6f68e60f9f1ee533c22b75335cd0d89504076d0f3d1876290995f24ea0614fc5a05c797362465d5cc705dcbabcbfc80586263c0ff9892c378f6199c8a75da2f2f1d2982d21ba54b56c11957efcf4a2f3841894e0ad93502e67bd42cf81283333fb163d61e7b13dcfe79770782deb8df8a57abf2c59d5b72ad8bea17ca36eecba704589c83e623662e0db21ee8e90683cd9f3c5707426979d2ba4c5bf2cc5190d9b9fdca99b30a9815de2f5f35701782dea332511b2faf7f02a46a62772229a923bec7b7f8e72852f9dd12128c7a7a50b1d2656f291e6971af941f72b2190bd1834861b85b908ca078cdedb5a2ee1a8a5db95e7f83df099f6f37371490fb2dc575f13ec008da31335bea6752deb4ec44eb9c585f0626bafead3664fdc12f8a4451e0239a395336b6a003c354b9a3583270b081cfecf8184dc0b8334cee93b9eb079e09589efbc44b4e4ee10c529e3cdd342279f5976832a2f273ede871c8c13f62054a862828d1e939ec818107c95abd4d215436d146a07d04885221c24c76f9c04f2da5014dbecfd9a9ea1f7e594743af36cc5e723f47d264f2a877bafc532dccff53edc3c03d840067a5f00c49d4f302292990ae4918d58921818cc6ae1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69839);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/15");

  script_cve_id("CVE-2013-1315", "CVE-2013-3158", "CVE-2013-3159");
  script_bugtraq_id(62167, 62219, 62225);
  script_osvdb_id(97131, 97134, 97135);
  script_xref(name:"MSFT", value:"MS13-073");
  script_xref(name:"IAVA", value:"2013-A-0171");

  script_name(english:"MS13-073: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2858300) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application installed on the remote Mac OS X host is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Microsoft Excel that
is affected by the following vulnerabilities :

  - Two memory corruption vulnerabilities exist due to the
    way the application handles objects in memory when
    parsing Office files. (CVE-2013-1315 / CVE-2013-3158)

  - An information disclosure vulnerability exists due to
    the way the application parses XML files containing
    external entities. (CVE-2013-3159)

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, it may be possible to leverage these
issues to read arbitrary files on the target system or execute
arbitrary code, subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-073");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

  fixed_version = '14.3.7';
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
