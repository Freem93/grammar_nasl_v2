#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84048);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id(
    "CVE-2015-3096",
    "CVE-2015-3097",
    "CVE-2015-3098",
    "CVE-2015-3099",
    "CVE-2015-3100",
    "CVE-2015-3101",
    "CVE-2015-3102",
    "CVE-2015-3103",
    "CVE-2015-3104",
    "CVE-2015-3105",
    "CVE-2015-3106",
    "CVE-2015-3107",
    "CVE-2015-3108"
  );
  script_bugtraq_id(
    75080,
    75081,
    75084,
    75085,
    75086,
    75087,
    75088,
    75089,
    75090
  );
  script_osvdb_id(
    123020,
    123021,
    123022,
    123023,
    123024,
    123025,
    123026,
    123027,
    123028,
    123029,
    123030,
    123031,
    123032
  );

  script_name(english:"Adobe Flash Player <= 17.0.0.188 Multiple Vulnerabilities (APSB15-11)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is equal or prior to version 17.0.0.188. It is, therefore, affected by
multiple vulnerabilities :

  - An unspecified vulnerability exists that allows an
    attacker to bypass the fix for CVE-2014-5333.
    (CVE-2015-3096)

  - An unspecified memory address randomization flaw exists
    on Windows 7 64-bit. (CVE-2015-3097)

  - Multiple unspecified flaws exist that allow a remote
    attacker to bypass the same-origin-policy, resulting in
    the disclosure of sensitive information. (CVE-2015-3098,
    CVE-2015-3099, CVE-2015-3102)

  - A remote code execution vulnerability exists due to an
    unspecified stack overflow flaw. (CVE-2015-3100)

  - A permission flaw exists in the Flash broker for IE
    that allows an attacker to perform a privilege
    escalation. (CVE-2015-3101)

  - Multiple use-after-free errors exist that allow an
    attacker to execute arbitrary code. (CVE-2015-3103,
    CVE-2015-3106, CVE-2015-3107)

  - An integer overflow condition exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-3104)

  - A memory corruption flaw exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this flaw, via specially crafted flash
    content, to corrupt memory and execute arbitrary code.
    (CVE-2015-3105)

  - An unspecified memory leak exists that allows an
    attacker to bypass the Address Space Layout
    Randomization (ASLR) feature. (CVE-2015-3108)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-11.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 18.0.0.160 or later.

Alternatively, Adobe has made version 13.0.0.292 available for those
installations that cannot be upgraded to 18.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Drawing Fill Shader Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/09");

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

    # Chrome Flash <= 17.0.0.188
    if(variant == "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"17.0.0.188",strict:FALSE) <= 0
    ) vuln = TRUE;

    # <= 13.0.0.289
    if(variant != "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"13.0.0.289",strict:FALSE) <= 0
    ) vuln = TRUE;

    # 14-17 <= 17.0.0.134
    if(variant != "Chrome_Pepper" &&
       ver =~ "^1[4-7]\." &&
       ver_compare(ver:ver,fix:"17.0.0.188",strict:FALSE) <= 0
    ) vuln = TRUE;

    if(vuln)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n Product : Browser plugin (for Firefox / Netscape / Opera)';
        fix = "18.0.0.160 / 13.0.0.292";
      }
      else if (variant == "ActiveX")
      {
        info += '\n Product : ActiveX control (for Internet Explorer)';
        fix = "18.0.0.160 / 13.0.0.292";
      }
      else if ("Chrome" >< variant)
      {
        info += '\n Product : Browser plugin (for Google Chrome)';
        if(variant == "Chrome")
          fix = "Upgrade to the latest version of Google Chrome.";
      }
      info += '\n  Path              : ' + file +
              '\n  Installed version : ' + ver;
      if (variant == "Chrome_Pepper")
        info += '\n  Fixed version     : 18.0.0.160 (Chrome PepperFlash)';
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
