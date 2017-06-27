#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95762);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/16 16:05:33 $");

  script_cve_id(
    "CVE-2016-7867",
    "CVE-2016-7868",
    "CVE-2016-7869",
    "CVE-2016-7870",
    "CVE-2016-7871",
    "CVE-2016-7872",
    "CVE-2016-7873",
    "CVE-2016-7874",
    "CVE-2016-7875",
    "CVE-2016-7876",
    "CVE-2016-7877",
    "CVE-2016-7878",
    "CVE-2016-7879",
    "CVE-2016-7880",
    "CVE-2016-7881",
    "CVE-2016-7890",
    "CVE-2016-7892"
  );
  script_bugtraq_id(
    94866,
    94870,
    94871,
    94873,
    94877
  );
  script_osvdb_id(
    148553,
    148554,
    148555,
    148556,
    148557,
    148558,
    148559,
    148560,
    148561,
    148562,
    148563,
    148564,
    148565,
    148566,
    148567,
    148568,
    148569
  );

  script_name(english:"Adobe Flash Player <= 23.0.0.207 Multiple Vulnerabilities (APSB16-39)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is equal or prior to version 23.0.0.207. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple use-after-free errors exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-7872, CVE-2016-7877, CVE-2016-7878,
    CVE-2016-7879, CVE-2016-7880, CVE-2016-7881,
    CVE-2016-7892)

  - Multiple buffer overflow conditions exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-7867, CVE-2016-7868, CVE-2016-7869,
    CVE-2016-7870)

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-7871, CVE-2016-7873, CVE-2016-7874,
    CVE-2016-7875, CVE-2016-7876)

  - An unspecified security bypass vulnerability exists.
    (CVE-2016-7890)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-39.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 24.0.0.186 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");


  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Flash_Player/installed");

# Identify vulnerable versions.
info = "";
fix = NULL;
variants = make_list(
  "Plugin",
  "ActiveX",
  "Chrome",
  "Chrome_Pepper"
);

# we're checking for versions less than *or equal to* the cutoff!
foreach variant (variants)
{
  vers = get_kb_list("SMB/Flash_Player/"+variant+"/Version/*");
  files = get_kb_list("SMB/Flash_Player/"+variant+"/File/*");

  if(isnull(vers) || isnull(files))
    continue;

  foreach key (keys(vers))
  {
    ver = vers[key];
    if(isnull(ver))
      continue;

    if(ver_compare(ver:ver,fix:"23.0.0.207",strict:FALSE) <= 0)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n  Product           : Browser Plugin (for Firefox / Netscape / Opera)';
        fix = "24.0.0.186";
      }
      else if (variant == "ActiveX")
      {
        info += '\n  Product           : ActiveX control (for Internet Explorer)';
        fix = "24.0.0.186";
      }
      else if ("Chrome" >< variant)
      {
        info += '\n  Product           : Browser Plugin (for Google Chrome)';
        if(variant == "Chrome")
          fix = "Upgrade to a version of Google Chrome running Flash Player 24.0.0.186";
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 24.0.0.186 (Chrome PepperFlash)';
      else if(!isnull(fix))
        info += '\n  Fixed version     : '+fix;
      info += '\n';
    }
  }
}

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:info);
}
else
{
  if (thorough_tests)
    exit(0, 'No vulnerable versions of Adobe Flash Player were found.');
  else
    exit(1, 'Google Chrome\'s built-in Flash Player may not have been detected because the \'Perform thorough tests\' setting was not enabled.');
}
