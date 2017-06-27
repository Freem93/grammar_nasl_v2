#TRUSTED 7e00fed6a4d0ba1d6b70e37785b814454221b9b238cd1ce8b4dafdf1ff38337db5544ef8bf8d1e2a4af9068dfa300141fc54a88a6995d06da67eeb4bc15b81d7590603fa0650a964b0fbe9ae34f60880c60987968fd2510b37b2b3ffe0a6cb7eb800927bb96af7175a60ab91516867615c5646f7adf34cf6508caf0422e1ccb1aaa652d1da1735466a3046934b06ab9cc69a1b141309940e5b22feaa40039dbcda3630b90ee6ca7bef0b5acd60d646e208406d2c37849eea8950bb0ada1879e14152b7b9f125ef8be3447376ea01cd6813c8ae616c8a524f4dcea90c565642d8ac5fd492e42ebaac916a5a8e0009cabcc116ef01cc637363654b35bf3a35c7b0cfba0efffe489c1b1a45ae9c306e7fc319ba79a692c2ef9233a13207abdb1ad24fe7d17195dea6461e00ccb532f565eb798b4839c8c866405bec6c09768b55f76edd336f1244311e788e2e79e3f4dd67a9dbc7a7e601afc9ed0995e1411a7f4d585013f0b2dafeca89781d75b69e4f645ecdc66604c14dd685eebad0cbab8efac986ccbc559c8534fbe172f93c19dd517b11176fcaca5aa25f0d2f2a11f4a2f1952a4bbab9d995edd1ea081e4d83d303680ae1406b6f9ff086c88f6e8eb6eaada0b220a7188099082b52ec2804378d55d00cfa024856e9939041b3fb66a3c5b1d06383f3564e0e963d949ca02d135fabf741ae4f662abe391090000c6f4fa32b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84740);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/15");

  script_cve_id("CVE-2015-2376", "CVE-2015-2379");
  script_osvdb_id(124598, 124600);
  script_xref(name:"MSFT", value:"MS15-070");
  script_xref(name:"IAVA", value:"2015-A-0163");

  script_name(english:"MS15-070: Vulnerability in Microsoft Office Could Allow Remote Code Execution (3072620)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Excel installed
that is affected by multiple remote code execution vulnerabilities due
to improper handling of objects in memory. A remote attacker can
exploit these vulnerabilities by convincing a user to open a specially
crafted file, resulting in the execution of arbitrary code in the
context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-070");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.

Note that Microsoft has re-released the patch to update the version
of Microsoft Office for Mac to version 14.5.3 to address a potential
issue with Microsoft Outlook for Mac. Microsoft recommends that this
update is applied.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011:mac");
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

  fixed_version = '14.5.3';
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
