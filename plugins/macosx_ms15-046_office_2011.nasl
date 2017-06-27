#TRUSTED 08e3f1148cd0d8dd00e3909f631f852978603cf1b9582cbc37bce530de2533a2deb59c2de8294288d4d5d0f1a39ecfc9090282aa61480e07c1c422b3f09b23d61a66edc0568c648daf3104ef70dfa9585fce8ac1d8033011a43a7654a72f34194610b4cc12e6290e9ec9834810c37640e5c282f6644bba9cc9fa8cf9edfc85daa5e5c77f4b1724b18f35154d8abfdb0af930c1282052c0220bfc6f5808e552daa418b38fd299373f8091aa1cd252d5fec8e2e58f49596774d664ef94f213079d7e70e934041f99089cae53897e1b82e1b8df5178de05b2ac020d48b7b0192caa5e0fa5556c14d7448f2167772874fdf177fc980b41ec45cf8ca6b11bf5dbc382a809bdf483fe04c5f7b322e7b083561003845b37b109bde8ce12da608bd2312075a4df361cb3d5f93804c994077d30c0292cdf3cd6467c692e3ebe365d993359a494a85a1b969f76ebe3e29f773d99eeda508d8d6b3be4f0dd10ee3a5fb9394dd866f2a47ab4bf72f06fbe6dd36172fd27ddca825ac1e33513107b279f9015d0ab6a6b929315f7141a5e82d85c14d1bc8073354d40cd8301a26c50a8135a208c241e7837d510275d33786ea670c75d6fdcd5421320c0a770cc2c256a11b157ae7cf86cf8376387ac42c47d2029f8ca7f12b9670a325130b9eeca686d41ddd0459d899003cdf7c6cb29256677a9bcb26a97b1c4f6872780579fe44986377f99c1
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83415);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/15");

  script_cve_id("CVE-2015-1682");
  script_bugtraq_id(74481);
  script_osvdb_id(122005);
  script_xref(name:"MSFT", value:"MS15-046");
  script_xref(name:"IAVA", value:"2015-A-0103");

  script_name(english:"MS15-046: Vulnerability in Microsoft Office Could Allow Remote Code Execution (3057181)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Word installed
that is affected by a remote code execution vulnerability due to
improper handling of objects in memory. A remote attacker can exploit
this vulnerability by convincing a user to open a specially crafted
file, resulting in execution of arbitrary code in the context of the
current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-046");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.

Note that Microsoft has re-released the patch to update the version
of Microsoft Office for Mac to version 14.5.1 to address a potential
issue with Microsoft Outlook for Mac. Microsoft recommends that this
update is applied.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_for_mac:2011");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac:2011");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_for_mac:2011");
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

  fixed_version = '14.5.0';
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
