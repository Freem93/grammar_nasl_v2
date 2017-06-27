#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81819);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id(
    "CVE-2015-0332",
    "CVE-2015-0333",
    "CVE-2015-0334",
    "CVE-2015-0335",
    "CVE-2015-0336",
    "CVE-2015-0337",
    "CVE-2015-0338",
    "CVE-2015-0339",
    "CVE-2015-0340",
    "CVE-2015-0341",
    "CVE-2015-0342"
  );
  script_bugtraq_id(
    73080,
    73081,
    73082,
    73083,
    73084,
    73085,
    73086,
    73087,
    73088,
    73089,
    73091
  );
  script_osvdb_id(
    119386,
    119479,
    119480,
    119481,
    119482,
    119483,
    119484,
    119485,
    119486,
    119487,
    119488
  );
  script_xref(name:"EDB-ID", value:"36962");

  script_name(english:"Flash Player <= 16.0.0.305 Multiple Vulnerabilities (APSB15-05)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Adobe Flash Player installed on the
remote Windows host is equal or prior to version 16.0.0.305. It is,
therefore, affected by the following vulnerabilities :

  - Multiple memory corruption issues exist due to not
    properly validating user input, which an attacker can
    exploit to execute arbitrary code. (CVE-2015-0332,
    CVE-2015-0333, CVE-2015-0335, CVE-2015-0339)

  - Multiple type confusions flaws exist, which an attacker
    can exploit to execute arbitrary code. (CVE-2015-0334,
    CVE-2015-0336)

  - An unspecified flaw exists that allows an attacker to
    bypass cross-domain policy. (CVE-2015-0337)

  - An integer overflow condition exists due to not properly
    validating user input, which an attacker can exploit to
    execute arbitrary code. (CVE-2015-0338)

  - An unspecified flaw exists that allows an attacker to
    bypass restrictions and upload arbitrary files.
    (CVE-2015-0340)

  - Multiple use-after-free errors exist that can allow an
    attacker to deference already freed memory and execute
    arbitrary code. (CVE-2015-0341, CVE-2015-0342)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-05.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 17.0.0.134 or later.

Alternatively, Adobe has made version 13.0.0.277 available for those
installations that cannot be upgraded to 17.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player NetConnection Type Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Flash_Player/installed");

# Identify vulnerable versions.
info = "";

# we're checking for versions less than *or equal to* the cutoff!
foreach variant (make_list("Plugin", "ActiveX", "Chrome", "Chrome_Pepper"))
{
  vers = get_kb_list("SMB/Flash_Player/"+variant+"/Version/*");
  files = get_kb_list("SMB/Flash_Player/"+variant+"/File/*");
  if (!isnull(vers) && !isnull(files))
  {
    foreach key (keys(vers))
    {
      ver = vers[key];

      if (ver)
      {
        iver = split(ver, sep:'.', keep:FALSE);
        for (i=0; i<max_index(iver); i++)
          iver[i] = int(iver[i]);

        if (
          (
            # Chrome Flash <= 16.0.0.305
            variant == "Chrome_Pepper" &&
            (
              (iver[0] < 16) ||
              (iver[0] == 16 && iver[1] == 0 && iver[2] == 0 && iver[3] <= 305)
            )
          ) ||
          (variant != "Chrome_Pepper" &&
            (
             (
               # < 13
               (
                 iver[0] < 13 ||
                 # 13.0.0.x <= 13.0.0.269
                 (
                   iver[0] == 13 &&
                   (
                     iver[1] == 0 &&
                     (
                       iver[2] == 0 &&
                       (
                         iver[3] <= 269
                       )
                     )
                   )
                 )
               ) ||
               # 14.0.0.x <= 17.0.0.134
               (
                 (
                   iver[0] >= 14 && iver[0] <= 15
                 ) ||
                 (
                   iver[0] == 16 &&
                   (
                     iver[1] == 0 &&
                     (
                       iver[2] == 0 &&
                       (
                         iver[3] <= 305
                       )
                     )
                   )
                 )
               )
             )
           )
         )
        )
        {
          num = key - ("SMB/Flash_Player/"+variant+"/Version/");
          file = files["SMB/Flash_Player/"+variant+"/File/"+num];
          if (variant == "Plugin")
          {
            info += '\n Product : Browser Plugin (for Firefox / Netscape / Opera)';
            fix = "17.0.0.134 / 13.0.0.277";
          }
          else if (variant == "ActiveX")
          {
            info += '\n Product : ActiveX control (for Internet Explorer)';
            fix = "17.0.0.134 / 13.0.0.277";
          }
          else if ("Chrome" >< variant)
          {
            info += '\n Product : Browser Plugin (for Google Chrome)';
          }
          info += '\n  Path              : ' + file +
                  '\n  Installed version : ' + ver;
          if (variant == "Chrome_Pepper")
            info += '\n  Fixed version     : 17.0.0.134 (Chrome PepperFlash)';
          else
            info += '\n  Fixed version     : '+fix;
          info += '\n';
        }
      }
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
