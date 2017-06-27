#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83365);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id(
    "CVE-2015-3044",
    "CVE-2015-3077",
    "CVE-2015-3078",
    "CVE-2015-3079",
    "CVE-2015-3080",
    "CVE-2015-3081",
    "CVE-2015-3082",
    "CVE-2015-3083",
    "CVE-2015-3084",
    "CVE-2015-3085",
    "CVE-2015-3086",
    "CVE-2015-3087",
    "CVE-2015-3088",
    "CVE-2015-3089",
    "CVE-2015-3090",
    "CVE-2015-3091",
    "CVE-2015-3092",
    "CVE-2015-3093"
  );
  script_bugtraq_id(
    74605,
    74608,
    74609,
    74610,
    74612,
    74613,
    74614,
    74616,
    74617
  );
  script_osvdb_id(
    120662,
    121927,
    121928,
    121929,
    121930,
    121931,
    121932,
    121933,
    121934,
    121935,
    121936,
    121937,
    121938,
    121939,
    121940,
    121941,
    121942,
    121943
  );

  script_name(english:"Adobe Flash Player <= 17.0.0.169 Multiple Vulnerabilities (APSB15-09)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Flash Player installed on the remote Windows host
is equal or prior to version 17.0.0.169. It is, therefore, affected by
multiple vulnerabilities :

  - An unspecified security bypass vulnerability exists that
    allows an attacker to disclose sensitive information.
    (CVE-2015-3044)

  - Multiple unspecified type confusion flaws exist that
    allow an attacker to execute arbitrary code.
    (CVE-2015-3077, CVE-2015-3084, CVE-2015-3086)

  - Multiple memory corruption flaws exist due to improper
    validation of user-supplied input. A remote attacker can
    exploit these flaws, via specially crafted flash
    content, to corrupt memory and execute arbitrary code.
    (CVE-2015-3078, CVE-2015-3089, CVE-2015-3090,
    CVE-2015-3093)

  - An unspecified security bypass exists that allows a
    context-dependent attacker to disclose sensitive
    information. (CVE-2015-3079)

  - An unspecified use-after-free error exists that allows
    an attacker to execute arbitrary code. (CVE-2015-3080)

  - An unspecified time-of-check time-of-use (TOCTOU) race
    condition exists that allows an attacker to bypass
    Protected Mode for Internet Explorer. (CVE-2015-3081)

  - Multiple validation bypass vulnerabilities exist that
    allow an attacker to read and write arbitrary data to
    the file system. (CVE-2015-3082, CVE-2015-3083,
    CVE-2015-3085)

  - An integer overflow condition exists due to improper
    validation of user-supplied input. This allows a
    context-dependent attacker to execute arbitrary code.
    (CVE-2015-3087)

  - A heap-based buffer overflow exists due to improper
    validation of user-supplied input. A remote attacker can
    exploit this to execute arbitrary code. (CVE-2015-3088)

  - Multiple unspecified memory leaks exist that allow an
    attacker to bypass the Address Space Layout
    Randomization (ASLR) feature. (CVE-2015-3091,
    CVE-2015-3092)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-09.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 17.0.0.188 or later.

Alternatively, Adobe has made version 13.0.0.289 available for those
installations that cannot be upgraded to 17.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player ShaderJob Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

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
       ver_compare(ver:ver,fix:"17.0.0.169",strict:FALSE) <= 0
    ) vuln = TRUE;

    # <= 13.0.0.277
    if(variant != "Chrome_Pepper" &&
       ver_compare(ver:ver,fix:"13.0.0.281",strict:FALSE) <= 0
    ) vuln = TRUE;

    # 14-17 <= 17.0.0.134
    if(variant != "Chrome_Pepper" &&
       ver =~ "^1[4567]\." &&
       ver_compare(ver:ver,fix:"17.0.0.169",strict:FALSE) <= 0
    ) vuln = TRUE;

    if(vuln)
    {
      num = key - ("SMB/Flash_Player/"+variant+"/Version/");
      file = files["SMB/Flash_Player/"+variant+"/File/"+num];
      if (variant == "Plugin")
      {
        info += '\n Product : Browser plugin (for Firefox / Netscape / Opera)';
        fix = "17.0.0.188 / 13.0.0.289";
      }
      else if (variant == "ActiveX")
      {
        info += '\n Product : ActiveX control (for Internet Explorer)';
        fix = "17.0.0.188 / 13.0.0.289";
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
        info += '\n  Fixed version     : 17.0.0.188 (Chrome PepperFlash)';
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
