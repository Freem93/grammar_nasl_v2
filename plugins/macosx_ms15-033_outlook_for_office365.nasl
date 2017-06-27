#TRUSTED 0507a522c29263640679af15e35d51349ce30d2acaa9b73042fc9aea94c18bede1e47121f0fbada3f749938687e262b0707fb749af69ae86aaf5d4fd197907edb43fc5b0cb9be54df501ea2d26d7d6f39bb9cfccc02829e579acbca2794d2e0410b461a637ed69aff28a78316f89a127ef2247d29f1935444f8889ac90607b2acc6326e646df4e4e02e4b4f1f4f59552c655f4daef1edbdfda61d6242a55fc894880011663b4fe9a0653b63847ef7318edf07b54223ed13cb634d1651cf3e0b09020a7b20e227e0baa312c66b9f663b1a7fba5354d0f9890653b55a27334393f4fc8ed2987083012ff1112defee259295a22822853b0be5d9468f0c81efec3fc3c940e2e0138abf57291da13e7c7a0279d64b272a32f86f285f55031afb9d75fb580fac08d3eb20f39571a344ced532a69eeb3949e1f09dcb744b5f06c931663ff9ba6f88aa840e5fc113d6400b711dc05404413ec1bb9e2e770c2c54e908d9de459535b2a924c8aa9d247d83a708f1b0b5dc4889a2c13f94d707b5b9517c6dba2a25fc27c781ec2c43832e08b63770cda1239f8a136912fa6ed6284b9790d9cda0bf29424c12ff5d26f5d3a707325527d3bfcb615b0b6f9d86240355bbee3ca1d0e22eecad3a1262d8dbcf8be5ec13dd1cedd55cb0d9f51b042e46c2da5d1c8117710713100b7fec0a1e7b10f97f6720702b047bd96cc8b455581f01035ecbf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82768);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/15");

  script_cve_id("CVE-2015-1639");
  script_bugtraq_id(73991);
  script_osvdb_id(120628);
  script_xref(name:"MSFT", value:"MS15-033");
  script_xref(name:"IAVA", value:"2015-A-0090");

  script_name(english:"MS15-033: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3048019)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Outlook
for Mac for Office 365 installed that is affected by a cross-site
scripting vulnerability due to improper sanitization of HTML strings.
A remote attacker can exploit this issue by convincing a user to open
a file or visit a website containing specially crafted content,
resulting in execution of arbitrary code in the context of the current
user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-033");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Outlook for Mac for Office 365.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:outlook_for_mac_for_office_365");
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

prod = 'Outlook for Mac for Office 365';
plist = '/Applications/Microsoft Outlook.app/Contents/Info.plist';
cmd =  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^15\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '15.9';
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
  set_kb_item(name:"www/0/XSS", value:TRUE);
  if (report_verbosity > 0) security_warning(port:0, extra:info);
  else security_warning(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) audit(AUDIT_NOT_INST, prod);
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
