#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88639);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/28 18:33:26 $");

  script_cve_id(
    "CVE-2016-0964", 
    "CVE-2016-0965", 
    "CVE-2016-0966", 
    "CVE-2016-0967", 
    "CVE-2016-0968", 
    "CVE-2016-0969", 
    "CVE-2016-0970", 
    "CVE-2016-0971", 
    "CVE-2016-0972", 
    "CVE-2016-0973", 
    "CVE-2016-0974", 
    "CVE-2016-0975", 
    "CVE-2016-0976", 
    "CVE-2016-0977", 
    "CVE-2016-0978", 
    "CVE-2016-0979", 
    "CVE-2016-0980", 
    "CVE-2016-0981", 
    "CVE-2016-0982", 
    "CVE-2016-0983", 
    "CVE-2016-0984", 
    "CVE-2016-0985"
  );
  script_osvdb_id(
    134259,
    134260,
    134261,
    134262,
    134263,
    134264,
    134265,
    134266,
    134267,
    134268,
    134269,
    134270,
    134271,
    134272,
    134273,
    134274,
    134275,
    134276,
    134277,
    134278,
    134279,
    134280
  );

  script_name(english:"Adobe Flash Player <= 20.0.0.286 Multiple Vulnerabilities (APSB16-04)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is prior or equal to version 20.0.0.286. It is, therefore, affected by
multiple vulnerabilities :

  - A type confusion error exists that allows a remote
    attacker to execute arbitrary code. (CVE-2016-0985)

  - Multiple use-after-free errors exist that allow a remote
    attacker to execute arbitrary code. (CVE-2016-0973,
    CVE-2016-0974, CVE-2016-0975, CVE-2016-0982,
    CVE-2016-0983, CVE-2016-0984)

  - A heap buffer overflow condition exist that allows an 
    attacker to execute arbitrary code. (CVE-2016-0971)

  - Multiple memory corruption issues exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2016-0964, CVE-2016-0965, CVE-2016-0966,
    CVE-2016-0967, CVE-2016-0968, CVE-2016-0969,
    CVE-2016-0970, CVE-2016-0972, CVE-2016-0976,
    CVE-2016-0977, CVE-2016-0978, CVE-2016-0979,
    CVE-2016-0980, CVE-2016-0981)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-04.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 20.0.0.306 or later.

Alternatively, Adobe has made version 18.0.0.329 available for those
installations that cannot be upgraded to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/09");

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

    # Chrome Flash <= 20.0.0.286
    if(variant == "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"20.0.0.286",strict:FALSE) <= 0
    ) vuln = TRUE;

    # <= 18.0.0.326
    if(variant != "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"18.0.0.326",strict:FALSE) <= 0
    ) vuln = TRUE;

    # 19 <= 20.0.0.286
    else if(variant != "Chrome_Pepper" && ver =~ "^(?:19|[2-9]\d)\.")
    {
      if (variant == "ActiveX" && ver_compare(ver:ver,fix:"20.0.0.286",strict:FALSE) <= 0)
        vuln = TRUE;
      else if (ver_compare(ver:ver,fix:"20.0.0.286",strict:FALSE) <= 0)
        vuln = TRUE;
    }

    if(vuln)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n  Product           : Browser Plugin (for Firefox / Netscape / Opera)';
        fix = "20.0.0.306 / 18.0.0.329";
      }
      else if (variant == "ActiveX")
      {
        info += '\n  Product           : ActiveX control (for Internet Explorer)';
        fix = "20.0.0.306 / 18.0.0.329";
      }
      else if ("Chrome" >< variant)
      {
        info += '\n  Product           : Browser Plugin (for Google Chrome)';
        if(variant == "Chrome")
          fix = "Upgrade to a version of Google Chrome running Flash Player 20.0.0.306";
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 20.0.0.306 (Chrome PepperFlash)';
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
