#TRUSTED 12a3b3d362140ebb2b393d06920b16e4a04746eb301c96ccf450f08e93e547f9f2c8ab166214e0abed31d34a677f1211f0367132a54d037fab07b9eade451231f07b996d5a96327344bca2a8caa66a76ab0055ab2f1e4f4c2bd07673b30cdeca9a4b7842873741b25cf180e78c2fa34db241ce39e7271b13cfaa32fe88a85a844d0791411b91b36cb61296644fcc8a53fb312765d0556a6a9c2a7450c52cd52fcd72a34323497bc3d7c415fb96561bb7b23033e44d1687730522a240efe334dd4e8c0a9843cd52e850521751ac95b685f354965fdb190c0b4906f80733c0c64cd620136b3ab4a9fc50bbb9fcdf051e038e215f9332e4857f4c1d24c3639f36b5f67fe8f305a23c5e7f7eb080d2006412b1af3aa46d919abea96cd1ae96cb07be22da46e75fedf544db5d4b91cb274c7fd9d03581105c5a4da9e5728ccb2b387b787076ef0f0dd4e2698b4619afcb6f91512b3fc017d855820218029e7ebb8cb0dccfcc1a89b4d179aa8abd2ee33b1e8fa4e160354cfdcc4794cbe6c2eb9ec2f35094777a4787182f783960495af48f68350535c80abd28a883acfa9e4f88b213d4d5612f9c7d8ed6920054abfbe6c397721e8f5b1f3477071dfebdbd537e214163566e189f00e8da9189c87eee5a242dc944893b97994b02e36bbef83b940893f221796c74054984ba748b01935cb7e2bf25092542987388e9c6592d8faf60ea
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70340);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/15");

  script_cve_id("CVE-2013-3889", "CVE-2013-3890");
  script_bugtraq_id(62824, 62829);
  script_osvdb_id(98219, 98220);
  script_xref(name:"MSFT", value:"MS13-085");

  script_name(english:"MS13-085: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2885080) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Microsoft Excel that
is affected by two memory corruption vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, it may be possible to leverage these
issues to execute arbitrary code, subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-085");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/09");

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

  fixed_version = '14.3.8';
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
