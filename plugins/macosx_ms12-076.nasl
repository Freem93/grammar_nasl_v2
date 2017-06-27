#TRUSTED 932fdb98ba3deddb86748956592f7f833b443b98e90d8d5cab1790f61d2694336fb1a667aec0bec35517a3096a6dabf82211e2a1764db2f89f8572800074a8e0037be61a6e9d0b823b47676c12c060b88b775135bdd3e5077dd10bcfeb4cfb0585a95d04cb037462d8cddc7c12a58405634566e47ac0b5085bfd328d568cd1eb80783984f57f4a5cc420dbeb9696c718eaa9db0cacae637bc93e2ce5aed039676b85687b99b850d464752fc479bdbef7de478715ec8635436a09e42660da978a03ba17e5e6813e53c10f247b4ecafc0b3d3bb840f7de0bced1f005b16b2215d7ee18521fe7b95376b87dba18ffaa5ad092c6f55289be59fbe1a5af55c496b6827f54e55e847279b77c534ac8c5644b19d9d057f80f2716ba78a9cb68a2be743ee6f77154a0821d4a103bfe39a765310d53526e8a457fd9c3f4642bc6e6b7cfddfe3bba5ff854e81ef7f132e76f2774042c7ac4eb9abe04881bf32b82a584b08804eb4dd324e127a43e8567f963c45445254dfb65dbd070fd5d5de9c25d71d19c3f753ed681b8b71ff3034f784f78dcc8b236fbe1003230afdd9a7681158b09f893cd8b8909bb18b00a5ddcce6b746b8ab7b6b606700d92cb15bfcdcae3a9d18d0c5010d16e25d950cf26195c9ef44d8e2a48d4a79a1bf259d801083e18918274ccfbe5b48b825e944de1851ab0ff9ea7f74541feab9931bdc5f1e9dcaacc5df6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62909);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/15");

  script_cve_id(
    "CVE-2012-1885",
    "CVE-2012-1886",
    "CVE-2012-1887",
    "CVE-2012-2543"
  );
  script_bugtraq_id(56425, 56426, 56430, 56431);
  script_osvdb_id(87270, 87271, 87272, 87273);
  script_xref(name:"MSFT", value:"MS12-076");

  script_name(english:"MS12-076: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2720184) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Excel that
is affected by the following vulnerabilities :

  - A heap-based buffer overflow vulnerability exists due to
    the way the application handles memory when opening
    Excel files. (CVE-2012-1885)

  - A memory corruption vulnerability exists due to the way
    the application handles memory when opening Excel
    files. (CVE-2012-1886)

  - A use-after-free vulnerability exists due to the way
    the application handles memory when opening Excel
    files. (CVE-2012-1887)

  - A stack-based buffer overflow vulnerability exists due
    to the way the application handles data structures while
    parsing Excel files. (CVE-2012-2543)

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, it may be possible to leverage these
issues to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-076");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office for Mac 2011 and
Office 2008 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/14");

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
path = '/Applications/Microsoft Office 2011';
plist = path + '/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist';
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

  fixed_version = '14.2.5';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}

prod = 'Office 2008 for Mac';
path = '/Applications/Microsoft Office 2008';
plist = path + '/Office/MicrosoftComponentPlugin.framework/Versions/12/Resources/Info.plist';
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

  fixed_version = '12.3.5';
  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  {
    info +=
      '\n  Product           : ' + prod +
      '\n  Path              : ' + path +
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
  if (max_index(keys(installs)) == 0) exit(0, "Office 2008 for Mac / Office for Mac 2011 is not installed.");
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
