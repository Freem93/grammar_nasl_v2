#TRUSTED 9d2fb1944d856a1958326f0f99680a3d4951bd473c7c8bde112b4968535e460a231c511d66549e3a930ff86d4b683fd7d8ed2431a7c10681d070f4a04bcff2a8437f740ce5d89f6d70f7da01df7c337695de69259027fdaf0897d4aef78e5bc72917c2873c8e4146881a365229ea152eb2e233f7e1442424e86e371be130e29474bd1ab08ee167df890933574e8a6327ccc64df226c1bf83a2e7c56dc886342a207333c9786d49b2be458dab71be7e66be4e6ef545a9ca67397c17ee0ae5b023ee810acbbcb6e9a0a734a25b13b5c19db9c6dfb7b38ebd4bd31fe6a08828618bd5b614596e68bf60efae9c43b4dcb6cf6117f8e4ec1a2bcd89470252e24e4661481443c27e179f7d8199a39ba7395cca9ff439926d49867fd0b4f45c18e6b918a1af75b0fe3026af26c4d1572ab3ce8e6d1fde191323d4147800a0503a8d9dd0d0aa8189182ab52266a93856b98ca47696955774dd43f573192860d891ee3dd43edbfa93f5ec0cf94b45f054f35003d8a105a2e509f5f654cbee586ef2cda9e47c6b4d054bf39cfca9acfcc2eb73993513477fe170250bcf8094411402008cbb3786e8a01a045abb6ed307a87c38e9adee0f60dc4af219d3a68db28ff8409e792f2986219da0a38c68cd0a71e0ece97ec9e239ba8802e983e289b9fe877213b309754e2f470a1ae91412d16e6438b1e4074f3784a3e69edc7b9bc7229b35b828
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59914);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/15");

  script_cve_id("CVE-2012-1894");
  script_bugtraq_id(54361);
  script_osvdb_id(83654);
  script_xref(name:"MSFT", value:"MS12-051");

  script_name(english:"MS12-051: Vulnerability in Microsoft Office for Mac Could Allow Elevation of Privilege (2721015) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application installed on the remote Mac OS X host is affected by an
elevation of privilege vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Microsoft Office for
Mac that is affected by a privilege escalation vulnerability in the
way that folder permissions are set in certain installations.  If an
attacker places a malicious executable in the Office 2011 folder and
lures a user into logging in and running that executable, he could
cause arbitrary code to be executed in the context of that user.

Note that this issue is primarily a risk on shared workstations, such
as in a library or an Internet cafe."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-051");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

  fixed_version = '14.2.3';
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
  if (report_verbosity > 0) security_warning(port:0, extra:info);
  else security_warning(0);

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
