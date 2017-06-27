#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85326);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/22 14:57:57 $");

  script_cve_id(
    "CVE-2015-3107",
    "CVE-2015-5125",
    "CVE-2015-5127",
    "CVE-2015-5128",
    "CVE-2015-5129",
    "CVE-2015-5130",
    "CVE-2015-5131",
    "CVE-2015-5132",
    "CVE-2015-5133",
    "CVE-2015-5134",
    "CVE-2015-5539",
    "CVE-2015-5540",
    "CVE-2015-5541",
    "CVE-2015-5544",
    "CVE-2015-5545",
    "CVE-2015-5546",
    "CVE-2015-5547",
    "CVE-2015-5548",
    "CVE-2015-5549",
    "CVE-2015-5550",
    "CVE-2015-5551",
    "CVE-2015-5552",
    "CVE-2015-5553",
    "CVE-2015-5554",
    "CVE-2015-5555",
    "CVE-2015-5556",
    "CVE-2015-5557",
    "CVE-2015-5558",
    "CVE-2015-5559",
    "CVE-2015-5560",
    "CVE-2015-5561",
    "CVE-2015-5562",
    "CVE-2015-5563",
    "CVE-2015-5564",
    "CVE-2015-5565",
    "CVE-2015-5566"
  );
  script_bugtraq_id(
    75087,
    76282,
    76283,
    76287,
    76288,
    76289,
    76291
  );
  script_osvdb_id(
    125910,
    125911,
    125912,
    125913,
    125914,
    125915,
    125916,
    125917,
    125918,
    125919,
    125920,
    125921,
    125922,
    125923,
    125924,
    125925,
    125926,
    125927,
    125928,
    125929,
    125930,
    125931,
    125932,
    125933,
    125934,
    125935,
    125936,
    125937,
    125938,
    125939,
    125940,
    125941,
    126086,
    126087,
    126597
  );

  script_name(english:"Adobe Flash Player <= 18.0.0.209 Multiple Vulnerabilities (APSB15-19)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is equal or prior to version 18.0.0.209. It is, therefore, affected by
the following vulnerabilities :

  - Multiple type confusion errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-5128,
    CVE-2015-5554, CVE-2015-5555, CVE-2015-5558,
    CVE-2015-5562)

  - An unspecified vulnerability exists related to vector
    length corruptions. (CVE-2015-5125)

  - Multiple user-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-5550,
    CVE-2015-5551, CVE-2015-3107, CVE-2015-5556,
    CVE-2015-5130, CVE-2015-5134, CVE-2015-5539,
    CVE-2015-5540, CVE-2015-5557, CVE-2015-5559,
    CVE-2015-5127, CVE-2015-5563, CVE-2015-5561,
    CVE-2015-5564, CVE-2015-5565, CVE-2015-5566)
  
  - Multiple heap buffer overflow conditions exist that
    allow an attacker to execute arbitrary code.
    (CVE-2015-5129, CVE-2015-5541)

  - Multiple buffer overflow conditions exist that allow an
    attacker to execute arbitrary code. (CVE-2015-5131,
    CVE-2015-5132, CVE-2015-5133)
  
  - Multiple memory corruption issues exist that allow an
    attacker to execute arbitrary code. (CVE-2015-5544,
    CVE-2015-5545, CVE-2015-5546, CVE-2015-5547,
    CVE-2015-5548, CVE-2015-5549, CVE-2015-5552,
    CVE-2015-5553)

  - An integer overflow condition exists that allows an
    attacker to execute arbitrary code. (CVE-2015-5560)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-19.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 18.0.0.232 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/11");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:flash_player");
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

    # Chrome Flash <= 18.0.0.209
    if(variant == "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"18.0.0.209",strict:FALSE) <= 0
    ) vuln = TRUE;

    # 14-18 <= 18.0.0.209
    if(variant != "Chrome_Pepper" &&
       ver =~ "^1[4-8]\." &&
       ver_compare(ver:ver,fix:"18.0.0.209",strict:FALSE) <= 0
    ) vuln = TRUE;

    if(vuln)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n Product : NPAPI Browser plugin (for Firefox / Netscape / Opera)';
        fix = "18.0.0.232";
      }
      else if (variant == "ActiveX")
      {
        info += '\n Product : ActiveX control (for Internet Explorer)';
        fix = "18.0.0.232";
      }
      else if (variant == "Chrome")
      {
        info += '\n Product : Browser plugin (for Google Chrome)';
        fix = "Upgrade to the latest version of Google Chrome.";
      }
      else if (variant == "Chrome_Pepper")
      {
        info += '\n Product : PPAPI Browser plugin (for Opera and Chromium)';
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 18.0.0.232 (Chrome PepperFlash)';
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
