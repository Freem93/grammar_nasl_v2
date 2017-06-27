#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86851);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/20 14:02:59 $");

  script_cve_id(
    "CVE-2015-7651",
    "CVE-2015-7652",
    "CVE-2015-7653",
    "CVE-2015-7654",
    "CVE-2015-7655",
    "CVE-2015-7656",
    "CVE-2015-7657",
    "CVE-2015-7658",
    "CVE-2015-7659",
    "CVE-2015-7660",
    "CVE-2015-7661",
    "CVE-2015-7662",
    "CVE-2015-7663",
    "CVE-2015-8042",
    "CVE-2015-8043",
    "CVE-2015-8044",
    "CVE-2015-8046"
  );
  script_osvdb_id(
    129999,
    130000,
    130001,
    130002,
    130003,
    130004,
    130005,
    130006,
    130007,
    130008,
    130009,
    130010,
    130011,
    130012,
    130013,
    130014,
    130015
  );

  script_name(english:"Adobe Flash Player <= 19.0.0.226 Multiple Vulnerabilities (APSB15-28)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is equal or prior to version 19.0.0.226. It is, therefore, affected by
multiple vulnerabilities :

  - A type confusion error exists that allows an attacker to
    execute arbitrary code. (CVE-2015-7659)

  - A security bypass vulnerability exists that allows an
    attacker to write arbitrary data to the file system
    under user permissions. (CVE-2015-7662)

  - Multiple use-after-free vulnerabilities exist that allow
    an attacker to execute arbitrary code. (CVE-2015-7651,
    CVE-2015-7652, CVE-2015-7653, CVE-2015-7654,
    CVE-2015-7655, CVE-2015-7656, CVE-2015-7657,
    CVE-2015-7658, CVE-2015-7660, CVE-2015-7661,
    CVE-2015-7663, CVE-2015-8042, CVE-2015-8043,
    CVE-2015-8044, CVE-2015-8046)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-28.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 19.0.0.245 or later.

Alternatively, Adobe has made version 18.0.0.261 available for those
installations that cannot be upgraded to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/11");

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

    # Chrome Flash <= 19.0.0.226
    if(variant == "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"19.0.0.226",strict:FALSE) <= 0
    ) vuln = TRUE;

    # <= 18.0.0.255
    if(variant != "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"18.0.0.255",strict:FALSE) <= 0
    ) vuln = TRUE;

    # 19 <= 19.0.0.226
    if(variant != "Chrome_Pepper" &&
       ver =~ "^(?:19|[2-9]\d)\." &&
       ver_compare(ver:ver,fix:"19.0.0.226",strict:FALSE) <= 0
    ) vuln = TRUE;

    if(vuln)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n  Product           : Browser Plugin (for Firefox / Netscape / Opera)';
        fix = "19.0.0.245 / 18.0.0.261";
      }
      else if (variant == "ActiveX")
      {
        info += '\n  Product           : ActiveX control (for Internet Explorer)';
        fix = "19.0.0.245 / 18.0.0.261";
      }
      else if ("Chrome" >< variant)
      {
        info += '\n  Product           : Browser Plugin (for Google Chrome)';
        if(variant == "Chrome")
          fix = "Upgrade to a version of Google Chrome running Flash Player 19.0.0.245";
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 19.0.0.245 (Chrome PepperFlash)';
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
    exit(1, 'Google Chrome\'s built-in Flash Player may not have been detected because the \'Perform thorough tests\' option was not enabled.');
}
