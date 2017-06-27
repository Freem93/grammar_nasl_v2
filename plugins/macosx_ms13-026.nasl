#TRUSTED 06b4398a865a64f825f0ab0bdefefc4a1ea3c6da8a91a6106797283682b55a5665725a464de67b961eaf9e351c729aa31c805b65b0be3d37fc92c6799c96c7cf5886b09e65f00a6924ef235a9068ab6c0309a085dd1fc0d463034e4f48168324593156338dcc017aa5b5baf11ef696cb33b57c2b74693ba52405ef39dcb1f399dec987c35fd3da4115cb5fde6ee2f7de2cc22b537b1d5b52436e2225fe46468e97aefb7bc78140f7c51e0f074e86ba17d63ee5119c6ae3cfb55654e780b58b3ac439736748c2184cb3f7a8e2c1e874cbe7c08106961d37b92a1e1f7910fa802ad67bbde641b728f26fa34265d91885ef55fe50385c71f6b81e53b95a008a94d1c4917f3ffe210b49c9b091d26df7bba1b44cb37730c4fab0538b872be3126dff57048981ad30027fa766024dd1fab46bb89b7d8b6d4fd38f8539e99b76a9a549fdbe58fb0bc046dd6f8d77ca69b645f7fb6077389fe7e52f494bca86df1dc8299e8ead4cdcbf6dec9b342af395ab14cc8413f9dcca275185f3603b6f18fcff7b087d3d8bdd0d07473f7c31204e3655748222b490a074a8791def4ba69c626493ca4a8b0f4a0805087d47a0929b3de37b92685db31a30e0ead1a89c028a13ca01e429242e55d2ea1edc1d519e58f217518ae7f20febe70ec12460e1d8c5efb407860f1bcab85b0e6a2f8f876bfc77d444e71f3947f08b94adbf73ba9348b7382f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65217);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/15");

  script_cve_id("CVE-2013-0095");
  script_bugtraq_id(58333);
  script_osvdb_id(91154);
  script_xref(name:"MSFT", value:"MS13-026");

  script_name(english:"MS13-026: Vulnerability in Office Outlook for Mac Could Allow Information Disclosure (2813682) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application installed on the remote Mac OS X host is affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Microsoft Outlook
that allows content from a remote server to be loaded without user
interaction when a user previews or opens a specially crafted HTML
email message.  This could allow an attacker to verify that an account
is actively used and that the email had been viewed."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-026");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released patches for Office for Mac 2011 and Office 2008
for Mac."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


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

  fixed_version = '14.3.2';
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

prod = 'Office 2008 for Mac';
plist = "/Applications/Microsoft Office 2008/Office/MicrosoftComponentPlugin.framework/Versions/12/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^12\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  fixed_version = '12.3.6';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}


# Report findings.
if (info)
{
  if (report_verbosity > 0) security_warning(port:0, extra:info);
  else security_warning(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac is not installed.");
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
