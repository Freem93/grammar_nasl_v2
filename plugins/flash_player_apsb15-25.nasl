#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86369);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/28 18:33:26 $");

  script_cve_id(
    "CVE-2015-5569",
    "CVE-2015-7625",
    "CVE-2015-7626",
    "CVE-2015-7627",
    "CVE-2015-7628",
    "CVE-2015-7629",
    "CVE-2015-7630",
    "CVE-2015-7631",
    "CVE-2015-7632",
    "CVE-2015-7633",
    "CVE-2015-7634",
    "CVE-2015-7643",
    "CVE-2015-7644"
  );

  script_osvdb_id(
    128762,
    128763,
    128764,
    128765,
    128766,
    128767,
    128768,
    128769,
    128770,
    128771,
    128772,
    128773,
    128774
  );

  script_name(english:"Adobe Flash Player <= 19.0.0.185 Multiple Vulnerabilities (APSB15-25)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is equal or prior to version 19.0.0.185. It is, therefore, affected by
multiple vulnerabilities :

  - An unspecified vulnerability exists related to the
    defense-in-depth feature in the Flash Broker API. No
    other details are available. (CVE-2015-5569)

  - Multiple unspecified memory corruption issues exist due
    to improper validation of user-supplied input. A remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2015-7625, CVE-2015-7626, CVE-2015-7627,
    CVE-2015-7630, CVE-2015-7633, CVE-2015-7634)

  - A unspecified vulnerability exists that can be exploited
    by a remote attacker to bypass the same-origin policy,
    allowing the disclosure of sensitive information.
    (CVE-2015-7628)

  - Multiple unspecified use-after-free errors exist that
    can be exploited by a remote attacker to deference
    already freed memory, potentially allowing the
    execution of arbitrary code. (CVE-2015-7629,
    CVE-2015-7631, CVE-2015-7643, CVE-2015-7644)

  - An unspecified buffer overflow condition exists due to
    improper validation of user-supplied input. An attacker
    can exploit this to execute arbitrary code.
    (CVE-2015-7632)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-25.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 19.0.0.207 or later.

Alternatively, Adobe has made version 18.0.0.252 available for those
installations that cannot be upgraded to the latest version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/13");

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

    # Chrome Flash <= 19.0.0.185
    if(variant == "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"19.0.0.185",strict:FALSE) <= 0
    ) vuln = TRUE;

    # all <= 18.0.0.241
    if(variant != "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"18.0.0.241",strict:FALSE) <= 0
    ) vuln = TRUE;

    # 19.0 <= 19.0.0.185
    if(variant != "Chrome_Pepper" &&
       ver =~ "^19\." &&
       ver_compare(ver:ver,fix:"19.0.0.185",strict:FALSE) <= 0
    ) vuln = TRUE;

    if(vuln)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n  Product           : Browser Plugin (for Firefox / Netscape / Opera)';
        fix = "19.0.0.207 / 18.0.0.252";
      }
      else if (variant == "ActiveX")
      {
        info += '\n  Product           : ActiveX control (for Internet Explorer)';
        fix = "19.0.0.207 / 18.0.0.252";
      }
      else if ("Chrome" >< variant)
      {
        info += '\n  Product           : Browser Plugin (for Google Chrome)';
        if(variant == "Chrome")
          fix = "Upgrade to a version of Google Chrome running Flash Player 19.0.0.207";
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 19.0.0.207 (Chrome PepperFlash)';
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
