#TRUSTED 79daeb49cd7ebbb02a8018b5894368ea5a2181ed52651109552e9ab38542b948c88c9adf412cc965e19ab9100765ea8acf83ec405aaa4d6bdbfc776a62ab8051e4bca9f6ce47f4ce5a5a3b341dcb1604e5deac6df8f982022f3c05f1ac8b968696dd3f61fffaa2c5dea0351747bdff0ce706d26f70e6ad9c87cbbb5cb05d976fd0d608276212cb248ea6450138e2e8b6497be31df665d007d052961693cccc9a0949c8f91f354d1ee8b3df458857dec3f2469a4ace8ec179c6a8fa661695c82e9ad7bb6e210866dcfc38bd4b4466c8ba62d364a39a89242b80dff2535247509ee70037f5263304541b7297b3470a7827c4ed48ba51e927ec1eae5ec0de3fa7211d069acc79e15bd5e6fe5947284290c2b018e3659d622e573f63990abe8fb3cb435447041d28376f03d8608699f26ce85b72699c9e701342408438e57dabd9da2fc4bcdead9d645940b318d79ad356d4b2cb4514172f4cfb6b1caeef46ab86c5c114cddae6b5fe47281af4381e7f29d8a66efb6a3415616c40348e5c1afec4cb0b9fd6ee507377b7e6ed1148cc3d6f2ba8f15f7801b3b57979ec71afe9d7b5fdc906b52994eb3304ed756d34c4babcc79459fe39a272df10508b52f6afc4bd0baaaa8f1264afa42cee69398f7510785ef0b840c03c45cffb6df1db5a219237d81528990bae13e83bfce97586312dec846b24c1eec3c19112aaeadd2a0f9a5f12
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79829);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/15");

  script_cve_id("CVE-2014-6357");
  script_bugtraq_id(71469);
  script_osvdb_id(115582);
  script_xref(name:"MSFT", value:"MS14-081");
  script_xref(name:"IAVA", value:"2014-A-0190");

  script_name(english:"MS14-081: Vulnerabilities in Microsoft Word and Microsoft Office Web Apps Could Allow Remote Code Execution (3017301) (Mac OS X)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Word that
is affected by a remote code execution vulnerability due to Microsoft
Word improperly handling objects in memory. A remote attacker can
exploit this vulnerability by convincing a user to open a specially
crafted Office file, resulting in execution of arbitrary code in the
context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-081");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

  fixed_version = '14.4.7';
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
