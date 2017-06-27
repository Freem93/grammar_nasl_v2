#TRUSTED 23241cc166a26dab23c4ec86e5befd692d818122dfa352e2db5e919492f1c5973ce646b97d4ae3476771fe8fb87d3c9e1e508ff41562c6bc642cc29080803fb8605f681fa279a14c96529678899729a1b127dc54dffa9bcfb5ce0f58be2544a7c781be057aff1bf7b136f5ca31c5fe8d9ad23f5761daf8d827a784cc140cd2065c8d7f29ece10720fa527db5368eceacb88ff86918e22c307f789a7b8cbd59e66212f8dd38246998d3a27f383b420b905ceb73d4777692f50dad99c5fa9663804178d1e6244b829e5bf064df12b1a52d62642405559316f3f7f1a896b131afb048daf49446f701cfc677340cdba512ef7729514abe2d91d44158bc222e4371d3bcb6a6652773f0200de7b74100b95547f719ba9052175ed2071547bc5575326838f092f2928e909d5e9d352694254b2c823fc445a24fe8e46e9ec4410db7690c97e7d03f17cfc1dabcdf2038f1eb462e6384417d11dce61c24b7466d477d3869a9b408bd77f2c0648cf19bf777b42b6bb8d3217b742c849cd3260313d748da0250d97cbf5a4e3c98e5d1c36922651e6e4206b6c3c65075ba9411aacd86ca5bc2b6b09210a15ccabef96cdc5ed74c856ec1d03a8b9331a38fff60424cee88af315f9dea2f7c561c2b565af80949459e8b6a2feec3c9836809848ed5cefcbd3633bc78941a21bb75efddd255180257793e0f9ffc25b8f208a5763cb6f7422f6f3e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59046);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/03");

  script_cve_id(
    "CVE-2012-0141",
    "CVE-2012-0142",
    "CVE-2012-0143",
    "CVE-2012-0183",
    "CVE-2012-0184",
    "CVE-2012-1847"
  );
  script_bugtraq_id(53342, 53344, 53373, 53374, 53375, 53379);
  script_osvdb_id(81724, 81725, 81726, 81727, 81728, 81732);
  script_xref(name:"MSFT", value:"MS12-029");
  script_xref(name:"MSFT", value:"MS12-030");

  script_name(english:"MS12-029 / MS12-030: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2680352 / 2663830) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by the following vulnerabilities :

  - A memory corruption vulnerability could be triggered
    when parsing specially crafted RTF-formatted data.
    (CVE-2012-0183)

  - Several memory corruption vulnerabilities could be
    triggered when reading a specially crafted Excel file.
    (CVE-2012-0141 / CVE-2012-0142 / CVE-2012-0143 /
    CVE-2012-0184)

  - A record parsing mismatch exists when opening a
    specially crafted Excel file. (CVE-2012-1847)

If a remote attacker can trick a user into opening a malicious file
using the affected install, these vulnerabilities could be leveraged
to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-157/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/279");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-029");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-030");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Office for Mac 2011 and Office 2008
for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
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

  fixed_version = '14.2.2';
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

  fixed_version = '12.3.3';
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
  if (report_verbosity > 0) security_hole(port:0, extra:info);
  else security_hole(0);

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
