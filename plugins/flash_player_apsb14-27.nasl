#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79835);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id(
    "CVE-2014-0580",
    "CVE-2014-0587",
    "CVE-2014-8443",
    "CVE-2014-9162",
    "CVE-2014-9163",
    "CVE-2014-9164"
  );
  script_bugtraq_id(
    71581,
    71582,
    71583,
    71584,
    71585,
    71586
  );
  script_osvdb_id(
    115557,
    115558,
    115559,
    115560,
    115561,
    115564
  );

  script_name(english:"Flash Player <= 15.0.0.239 Multiple Vulnerabilities (APSB14-27)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Adobe Flash Player
installed on the remote Windows host is equal or prior to 15.0.0.239.
It is, therefore, affected by the following vulnerabilities :

  - A security bypass vulnerability that allows an attacker
    to bypass the same-origin policy. (CVE-2014-0580)

  - Multiple memory corruption vulnerabilities that allow an
    attacker to execute arbitrary code. (CVE-2014-0587,
    CVE-2014-9164)

  - A use-after-free vulnerability that can result in
    arbitrary code execution. (CVE-2014-8443)

  - An unspecified information disclosure vulnerability.
    (CVE-2014-9162)

  - A stack-based buffer overflow vulnerability that can be
    exploited to execute arbitrary code or elevate
    privileges. (CVE-2014-9163)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-27.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 16.0.0.235 or later.

Alternatively, Adobe has made version 13.0.0.259 available for those
installations that cannot be upgraded to 16.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/09");

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
            # Chrome Flash <= 15.0.0.239
            variant == "Chrome_Pepper" &&
            (
              (iver[0] < 15) ||
              (iver[0] == 15 && iver[1] == 0 && iver[2] == 0 && iver[3] <= 239)
            )
          ) ||
          (variant != "Chrome_Pepper" &&
            (
             (
               # < 13
               (
                 iver[0] < 13 ||
                 # 13.0.0.x <= 13.0.0.258
                 (
                   iver[0] == 13 &&
                   (
                     iver[1] == 0 &&
                     (
                       iver[2] == 0 &&
                       (
                         iver[3] <= 258
                       )
                     )
                   )
                 )
               ) ||
               # 14.0.0.x <= 15.0.0.239
               (
                 iver[0] == 14 ||
                 (
                   iver[0] == 15 &&
                   (
                     iver[1] == 0 &&
                     (
                       iver[2] == 0 &&
                       (
                         iver[3] <= 239
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
            fix = "16.0.0.235 / 13.0.0.259";
          }
          else if (variant == "ActiveX")
          {
            info += '\n Product : ActiveX control (for Internet Explorer)';
            fix = "16.0.0.235 / 13.0.0.259";
          }
          else if ("Chrome" >< variant)
          {
            info += '\n Product : Browser Plugin (for Google Chrome)';
          }
          info += '\n  Path              : ' + file +
                  '\n  Installed version : ' + ver;
          if (variant == "Chrome_Pepper")
            info += '\n  Fixed version     : 16.0.0.235 (Chrome PepperFlash)';
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
