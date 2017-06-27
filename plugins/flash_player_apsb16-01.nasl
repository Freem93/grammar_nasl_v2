#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87657);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/28 18:33:26 $");

  script_cve_id(
    "CVE-2015-8459",
    "CVE-2015-8460",
    "CVE-2015-8634",
    "CVE-2015-8635",
    "CVE-2015-8636",
    "CVE-2015-8638",
    "CVE-2015-8639",
    "CVE-2015-8640",
    "CVE-2015-8641",
    "CVE-2015-8642",
    "CVE-2015-8643",
    "CVE-2015-8644",
    "CVE-2015-8645",
    "CVE-2015-8646",
    "CVE-2015-8647",
    "CVE-2015-8648",
    "CVE-2015-8649",
    "CVE-2015-8650",
    "CVE-2015-8651"
  );
  script_osvdb_id(
    132309,
    132310,
    132311,
    132312,
    132313,
    132314,
    132315,
    132316,
    132317,
    132318,
    132319,
    132320,
    132321,
    132322,
    132323,
    132324,
    132325,
    132326,
    132327
  );

  script_name(english:"Adobe Flash Player <= 20.0.0.235 Multiple Vulnerabilities (APSB16-01)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is equal or prior to version 20.0.0.235. It is, therefore, affected by
multiple vulnerabilities :

  - A type confusion error exists that a remote attacker can
    exploit to execute arbitrary code. (CVE-2015-8644)

  - An integer overflow condition exists that a remote
    attacker can exploit to execute arbitrary code.
    (CVE-2015-8651)

  - Multiple use-after-free errors exist that a remote
    attacker can exploit to execute arbitrary code.
    (CVE-2015-8634, CVE-2015-8635, CVE-2015-8638,
    CVE-2015-8639, CVE-2015-8640, CVE-2015-8641,
    CVE-2015-8642, CVE-2015-8643, CVE-2015-8646,
    CVE-2015-8647, CVE-2015-8648, CVE-2015-8649,
    CVE-2015-8650)

  - Multiple memory corruption issues exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2015-8459, CVE-2015-8460, CVE-2015-8636,
    CVE-2015-8645)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-01.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 20.0.0.267 or later.

Alternatively, Adobe has made version 18.0.0.324 available for those
installations that cannot be upgraded to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

    # Chrome Flash <= 20.0.0.228
    if(variant == "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"20.0.0.228",strict:FALSE) <= 0
    ) vuln = TRUE;

    # <= 18.0.0.268 
    if(variant != "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"18.0.0.268",strict:FALSE) <= 0
    ) vuln = TRUE;

    # 19 <= 20.0.0.235
    else if(variant != "Chrome_Pepper" && ver =~ "^(?:19|[2-9]\d)\.")
    {
      if (variant == "ActiveX" && ver_compare(ver:ver,fix:"20.0.0.228",strict:FALSE) <= 0)
        vuln = TRUE;
      else if (ver_compare(ver:ver,fix:"20.0.0.235",strict:FALSE) <= 0)
        vuln = TRUE;
    }

    if(vuln)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n  Product           : Browser Plugin (for Firefox / Netscape / Opera)';
        fix = "20.0.0.267 / 18.0.0.324";
      }
      else if (variant == "ActiveX")
      {
        info += '\n  Product           : ActiveX control (for Internet Explorer)';
        fix = "20.0.0.267 / 18.0.0.324";
      }
      else if ("Chrome" >< variant)
      {
        info += '\n  Product           : Browser Plugin (for Google Chrome)';
        if(variant == "Chrome")
          fix = "Upgrade to a version of Google Chrome running Flash Player 20.0.0.267";
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 20.0.0.267 (Chrome PepperFlash)';
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
