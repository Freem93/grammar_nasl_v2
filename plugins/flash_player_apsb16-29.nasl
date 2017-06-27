#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93461);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id(
    "CVE-2016-4271",
    "CVE-2016-4272",
    "CVE-2016-4274",
    "CVE-2016-4275",
    "CVE-2016-4276",
    "CVE-2016-4277",
    "CVE-2016-4278",
    "CVE-2016-4279",
    "CVE-2016-4280",
    "CVE-2016-4281",
    "CVE-2016-4282",
    "CVE-2016-4283",
    "CVE-2016-4284",
    "CVE-2016-4285",
    "CVE-2016-4287",
    "CVE-2016-6921",
    "CVE-2016-6922",
    "CVE-2016-6923",
    "CVE-2016-6924",
    "CVE-2016-6925",
    "CVE-2016-6926",
    "CVE-2016-6927",
    "CVE-2016-6929",
    "CVE-2016-6930",
    "CVE-2016-6931",
    "CVE-2016-6932"
  );
  script_osvdb_id(
    144112,
    144113,
    144114,
    144115,
    144116,
    144117,
    144118,
    144119,
    144120,
    144121,
    144122,
    144123,
    144124,
    144125,
    144126,
    144127,
    144128,
    144129,
    144130,
    144131,
    144132,
    144133,
    144134,
    144135,
    144136,
    144138
  );

  script_name(english:"Adobe Flash Player <= 22.0.0.211 Multiple Vulnerabilities (APSB16-29)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is equal or prior to version 22.0.0.211. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple security bypass vulnerabilities exist that
    allow an unauthenticated, remote attacker to disclose
    sensitive information. (CVE-2016-4271, CVE-2016-4277,
    CVE-2016-4278)

  - Multiple use-after-free errors exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-4272, CVE-2016-4279, CVE-2016-6921,
    CVE-2016-6923, CVE-2016-6925, CVE-2016-6926,
    CVE-2016-6927, CVE-2016-6929, CVE-2016-6930,
    CVE-2016-6931, CVE-2016-6932)

  - Multiple memory corruption issues exist that allow an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-4274, CVE-2016-4275, CVE-2016-4276,
    CVE-2016-4280, CVE-2016-4281, CVE-2016-4282,
    CVE-2016-4283, CVE-2016-4284, CVE-2016-4285,
    CVE-2016-6922, CVE-2016-6924)

  - An integer overflow condition exists that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. (CVE-2016-4287)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-29.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 23.0.0.162 or later.

Alternatively, Adobe has made version 18.0.0.375 available for those
installs that cannot be upgraded to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/13");

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

    # Chrome Flash <= 23.0.0.162
    if(variant == "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"23.0.0.162",strict:FALSE) == -1
    ) vuln = TRUE;

    # <= 18.0.0.375
    if(variant != "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"18.0.0.375",strict:FALSE) == -1
    ) vuln = TRUE;

    # 14-17 <= 22.0.0.211
    if(variant != "Chrome_Pepper" &&
       ver =~ "^(?:19|[2-9]\d)\." &&
       ver_compare(ver:ver,fix:"22.0.0.211",strict:FALSE) == -1
    ) vuln = TRUE;

    if(vuln)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n  Product           : Browser Plugin (for Firefox / Netscape / Opera)';
        fix = "23.0.0.162 / 18.0.0.375";
      }
      else if (variant == "ActiveX")
      {
        info += '\n  Product           : ActiveX control (for Internet Explorer)';
        fix = "23.0.0.162 / 18.0.0.375";
      }
      else if ("Chrome" >< variant)
      {
        info += '\n  Product           : Browser Plugin (for Google Chrome)';
        if(variant == "Chrome")
          fix = "Upgrade to a version of Google Chrome running Flash Player 23.0.0.162";
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 23.0.0.162 (Chrome PepperFlash)';
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
