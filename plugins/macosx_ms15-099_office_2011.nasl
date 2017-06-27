#TRUSTED 853f6f14aaea543cd8b57bea6a4311900024bd7c7eaeee508b554de71394753e2e04d643dc7b077c830b17c336e77af157f754e47f910d10dd3ca1516b299ca4f95885b33d72579640fa6f0818a2e2f99785daa7e01b4637bdb4bc3d973743e09540c4d94d32032f305bd6319735a622ee32fc3998c0c228279f2976e5de61cf7724d6c0590d0fe9cfa25038fddd1e7528b898e09cdfc60f0639c5b58884828d9b1105dd99287366ed3fbd9d7c1fb9818f8d57600872f8362fccf61aba5d6f7dafb19f81cb5fed04f3657f605a5d84676bf6bbd95c996fcf5ff11e62b6528a32b0a2389d802f68e3a28fc6239de3c76b48811238ca49514bf44d3661340cfdf2670249f1f466b4ba04efe99368c34020a7fb6e32daeedc9324d3245d29d5f9f7ae56408fb0e898d6b37427f808fbef7cb6a33486764f6387eeb90fca5baf741ac93b8ea87eb329f1e9247bc5408ef491791c43a99018af622e87eb157d35ab0c16089c01378551e26ab4392f6cf1bc4b978c328d7859acb9b87f5d0c9a772d5effba04d6ff5a0b7de7c67f55d2b6a07622cb8928118e41c38e5315b00940f23ed1616b8d74adea65ab09d83a38a2ccac7b153ae252f2107d3c888d61f3dd6eb8a8f4e3817324bc5eaaddc4d475e108af9f29f4cafa5f466e2472fdc23fb967e7b1b94a6a339911ba4c30d2504681f7f2016df86404a9e3d4b5c7c9e591470bab
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85878);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/15");

  script_cve_id("CVE-2015-2520", "CVE-2015-2523");
  script_bugtraq_id(76561, 76564);
  script_osvdb_id(127212, 127214);
  script_xref(name:"MSFT", value:"MS15-099");
  script_xref(name:"IAVA", value:"2015-A-0214");
  script_xref(name:"EDB-ID", value:"38214");
  script_xref(name:"EDB-ID", value:"38215");

  script_name(english:"MS15-099: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3089664) (Mac OS X)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Office installed
that is affected by multiple remote code execution vulnerabilities due
to improper handling of objects in memory. A remote attacker can
exploit these vulnerabilities by convincing a user to open a specially
crafted file in Microsoft Office, resulting in the execution of
arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-099");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Office for Mac 2011 and for Office
2016 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011:mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2016:mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac:2011");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac:2016");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

# Gather version info for Office 2011
info = '';
installs = make_array();
office_2011_found = FALSE;

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
  if (version !~ "^14\.")
    exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  office_2011_found = TRUE;
  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.5.5';
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

# Checking for Office 2016. The same path for the overall install
# doesn't exist for 2016, so we need to check each app, as each one
# is listed as needing an update to 15.14.

apps = make_list(
         "Microsoft Outlook",
         "Microsoft Excel",
         "Microsoft Word",
         "Microsoft PowerPoint",
         "Microsoft OneNote");
fix_2016 = "15.14.0";

office_2016_found = FALSE;
foreach app (apps)
{
  plist = "/Applications/"+app+".app/Contents/Info.plist";
  cmd =
    'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
  ver_2016 = exec_cmd(cmd:cmd);

  # check all of the applications
  if (!strlen(ver_2016))
    continue;

  office_2016_found = TRUE;
  if(ver_2016 =~ "^15\." &&
     ver_compare(ver:ver_2016, fix:fix_2016, strict:FALSE) < 0)
  {
    vuln[app] = ver_2016;
  }
}

if (office_2016_found)
{
    foreach app (keys(vuln))
    {
      info +=
        '\n  Product           : ' + app +
        '\n  Installed version : ' + vuln[app] +
        '\n  Fixed version     : ' + fix_2016 + '\n';
    }
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
  msg = '';
  is = 'is';

  if (! office_2016_found && ! office_2011_found)
    audit(AUDIT_NOT_INST, "Office for Mac 2011/2016");
  if (office_2011_found)
  {
    msg = "Office for Mac 2011";
  }
  if (office_2016_found)
  {
    if (office_2011_found)
    {
      msg += " and ";
      is = "are";
    }
    msg += "Office 2016 for Mac";
  }

  exit(0, msg + " " + is + " not vulnerable.");
}
