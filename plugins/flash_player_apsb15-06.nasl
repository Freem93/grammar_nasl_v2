#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82781);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id(
    "CVE-2015-0346",
    "CVE-2015-0347",
    "CVE-2015-0348",
    "CVE-2015-0349",
    "CVE-2015-0350",
    "CVE-2015-0351",
    "CVE-2015-0352",
    "CVE-2015-0353",
    "CVE-2015-0354",
    "CVE-2015-0355",
    "CVE-2015-0356",
    "CVE-2015-0357",
    "CVE-2015-0358",
    "CVE-2015-0359",
    "CVE-2015-0360",
    "CVE-2015-3038",
    "CVE-2015-3039",
    "CVE-2015-3040",
    "CVE-2015-3041",
    "CVE-2015-3042",
    "CVE-2015-3043",
    "CVE-2015-3044"
  );
  script_bugtraq_id(
    74062,
    74064,
    74065,
    74066,
    74067,
    74068,
    74069
  );
  script_osvdb_id(
    120641,
    120642,
    120643,
    120644,
    120645,
    120646,
    120647,
    120648,
    120649,
    120650,
    120651,
    120652,
    120653,
    120654,
    120655,
    120656,
    120657,
    120658,
    120659,
    120660,
    120661,
    120662
  );

  script_name(english:"Adobe Flash Player <= 17.0.0.134 Multiple Vulnerabilities (APSB15-06)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is equal or prior to version 17.0.0.134. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple double-free errors exist that allow an attacker
    to execute arbitrary code. (CVE-2015-0346,
    CVE-2015-0359)

  - Multiple memory corruption flaws exist due to improper
    validation of user-supplied input. A remote attacker can
    exploit these flaws, via specially crafted flash
    content, to corrupt memory and execute arbitrary code.
    (CVE-2015-0347, CVE-2015-0350, CVE-2015-0352,
    CVE-2015-0353, CVE-2015-0354, CVE-2015-0355,
    CVE-2015-0360, CVE-2015-3038, CVE-2015-3041,
    CVE-2015-3042, CVE-2015-3043)

  - A unspecified buffer overflow condition exists due to
    improper validation of user-supplied input. A remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2015-0348)

  - Multiple unspecified use-after-free errors exist that
    allow an attacker to execute arbitrary code.
    (CVE-2015-0349, CVE-2015-0351, CVE-2015-0358,
    CVE-2015-3039)

  - An unspecified type confusion flaw exists that allows
    an attacker to execute arbitrary code. (CVE-2015-0356)

  - Multiple unspecified memory leaks exist that allows an
    attacker to bypass the Address Space Layout
    Randomization (ASLR) feature. (CVE-2015-0357,
    CVE-2015-3040)

  - An unspecified security bypass flaw exists that allows
    an attacker to disclose information. (CVE-2015-3044)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-06.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 17.0.0.169 or later.

Alternatively, Adobe has made version 13.0.0.281 and 11.2.202.457
available for those installations that cannot be upgraded to 17.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Nellymoser Audio Decoding Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/14");

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

    # Chrome Flash <= 17.0.0.134
    if(variant == "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"17.0.0.134",strict:FALSE) <= 0
    ) vuln = TRUE;

    # <= 13.0.0.277
    if(variant != "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"13.0.0.277",strict:FALSE) <= 0
    ) vuln = TRUE;

    # 14-17 <= 17.0.0.134
    if(variant != "Chrome_Pepper" &&
       ver =~ "^1[4567]\." &&
       ver_compare(ver:ver,fix:"17.0.0.134",strict:FALSE) <= 0
    ) vuln = TRUE;

    if(vuln)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n Product : Browser Plugin (for Firefox / Netscape / Opera)';
        fix = "17.0.0.169 / 13.0.0.281";
      }
      else if (variant == "ActiveX")
      {
        info += '\n Product : ActiveX control (for Internet Explorer)';
        fix = "17.0.0.169 / 13.0.0.281";
      }
      else if ("Chrome" >< variant)
      {
        info += '\n Product : Browser Plugin (for Google Chrome)';
        if(variant == "Chrome")
          fix = "Upgrade to a version of Google Chrome after version 21";
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 17.0.0.169 (Chrome PepperFlash)';
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
