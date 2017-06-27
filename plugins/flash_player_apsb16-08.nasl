#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89834);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/07/18 20:50:58 $");

  script_cve_id(
    "CVE-2016-0960",
    "CVE-2016-0961",
    "CVE-2016-0962",
    "CVE-2016-0963",
    "CVE-2016-0986",
    "CVE-2016-0987",
    "CVE-2016-0988",
    "CVE-2016-0989",
    "CVE-2016-0990",
    "CVE-2016-0991",
    "CVE-2016-0992",
    "CVE-2016-0993",
    "CVE-2016-0994",
    "CVE-2016-0995",
    "CVE-2016-0996",
    "CVE-2016-0997",
    "CVE-2016-0998",
    "CVE-2016-0999",
    "CVE-2016-1000",
    "CVE-2016-1001",
    "CVE-2016-1002",
    "CVE-2016-1005",
    "CVE-2016-1010"
  );
  script_bugtraq_id(
    84308,
    84308,
    84310,
    84311,
    84312
  );
  script_osvdb_id(
    135679,
    135680,
    135681,
    135682,
    135683,
    135684,
    135685,
    135686,
    135687,
    135688,
    135689,
    135690,
    135691,
    135692,
    135693,
    135694,
    135695,
    135696,
    135697,
    135698,
    135699,
    135700,
    135701
  );

  script_name(english:"Adobe Flash Player <= 20.0.0.306 Multiple Vulnerabilities (APSB16-08)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is prior or equal to version 20.0.0.306. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple integer overflow conditions exist that allow an
    attacker to execute arbitrary code. (CVE-2016-0963,
    CVE-2016-0993, CVE-2016-1010)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2016-0987,
    CVE-2016-0988, CVE-2016-0990, CVE-2016-0991,
    CVE-2016-0994, CVE-2016-0995, CVE-2016-0996,
    CVE-2016-0997, CVE-2016-0998, CVE-2016-0999,
    CVE-2016-1000)

  - A heap overflow condition exists that allows an attacker
    to execute arbitrary code. (CVE-2016-1001)

  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2016-0960,
    CVE-2016-0961, CVE-2016-0962, CVE-2016-0986,
    CVE-2016-0989, CVE-2016-0992, CVE-2016-1002,
    CVE-2016-1005)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-08.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 21.0.0.182 or later.

Alternatively, Adobe has made version 18.0.0.333 available for those
installations that cannot be upgraded to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Flash_Player/installed");

# Identify vulnerable versions.
info = "";
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

    vuln = FALSE;

    # Chrome Flash <=   20.0.0.306
    if(variant == "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"20.0.0.306",strict:FALSE) <= 0
    ) vuln = TRUE;

    # <= 18.0.0.329
    if(variant != "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"18.0.0.329",strict:FALSE) <= 0
    ) vuln = TRUE;

    # 19 <= 20.0.0.306
    else if(variant != "Chrome_Pepper" && ver =~ "^(?:19|[2-9]\d)\.")
    {
      if (variant == "ActiveX" && ver_compare(ver:ver,fix:"20.0.0.306",strict:FALSE) <= 0)
        vuln = TRUE;
      else if (ver_compare(ver:ver,fix:"20.0.0.306",strict:FALSE) <= 0)
        vuln = TRUE;
    }

    if(vuln)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n  Product           : Browser Plugin (for Firefox / Netscape / Opera)';
        fix = "21.0.0.182 / 18.0.0.333";
      }
      else if (variant == "ActiveX")
      {
        info += '\n  Product           : ActiveX control (for Internet Explorer)';
        fix = "21.0.0.182 / 18.0.0.333";
      }
      else if ("Chrome" >< variant)
      {
        info += '\n  Product           : Browser Plugin (for Google Chrome)';
        if(variant == "Chrome")
          fix = "Upgrade to a version of Google Chrome running Flash Player 21.0.0.182";
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 21.0.0.182 (Chrome PepperFlash)';
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

  if (report_verbosity > 0) security_hole(port:port, extra:info);
  else security_hole(port);
}
else
{
  if (thorough_tests)
    exit(0, 'No vulnerable versions of Adobe Flash Player were found.');
  else
    exit(1, 'Google Chrome\'s built-in Flash Player may not have been detected because the \'Perform thorough tests\' setting was not enabled.');
}
