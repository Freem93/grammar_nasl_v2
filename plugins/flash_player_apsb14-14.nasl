#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73994);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id(
    "CVE-2014-0510",
    "CVE-2014-0516",
    "CVE-2014-0517",
    "CVE-2014-0518",
    "CVE-2014-0519",
    "CVE-2014-0520"
  );
  script_bugtraq_id(66241, 67361, 67364, 67371, 67372, 67373);
  script_osvdb_id(104585, 106886, 106887, 106888, 106889, 106890);

  script_name(english:"Flash Player <= 13.0.0.206 Multiple Vulnerabilities (APSB14-14)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Flash Player installed on
the remote Windows host is equal or prior to 13.0.0.206. It is,
therefore, potentially affected by the following vulnerabilities :

  - An unspecified use-after-free vulnerability exists that
    could allow for the execution of arbitrary code.
    (CVE-2014-0510)

  - An unspecified vulnerability exists that could be used
    to bypass the same origin policy. (CVE-2014-0516)

  - Multiple, unspecified security bypass vulnerabilities
    exist. (CVE-2014-0517, CVE-2014-0518, CVE-2014-0519,
    CVE-2014-0520)");
  script_set_attribute(attribute:"see_also", value:"http://www.pwn2own.com/2014/03/pwn2own-results-thursday-day-two/");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-14.html");
  # http://blogs.adobe.com/flashplayer/2014/03/upcoming-changes-to-flash-players-extended-support-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01ced53b");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Flash Player version 13.0.0.214 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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
            # Chrome Flash <= 13.0.0.206
            variant == "Chrome_Pepper" &&
            (iver[0] == 13 && iver[1] == 0 && iver[2] == 0 && iver[3] <= 206)
          ) ||
          (variant != "Chrome_Pepper" &&
            (
             # < 13
             iver[0] < 13 ||
             # 13.0.0.x <= 13.0.0.206
             (
               iver[0] == 13 &&
               (
                 iver[1] == 0 &&
                 (
                   iver[2] == 0 &&
                   (
                     iver[3] <= 206
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
          }
          else if (variant == "ActiveX")
          {
            info += '\n Product : ActiveX control (for Internet Explorer)';
          }
          else if ("Chrome" >< variant)
          {
            info += '\n Product : Browser Plugin (for Google Chrome)';
          }
          info += '\n  Path              : ' + file +
                  '\n  Installed version : ' + ver;
          if (variant == "Chrome_Pepper")
            info += '\n  Fixed version     : 13.0.0.214 (Chrome PepperFlash)';
          else
          {
            fix = "13.0.0.214";
            info += '\n  Fixed version     : '+fix;
          }
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
