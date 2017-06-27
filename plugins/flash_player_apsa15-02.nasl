#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81127);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id(
    "CVE-2015-0313",
    "CVE-2015-0314",
    "CVE-2015-0315",
    "CVE-2015-0316",
    "CVE-2015-0317",
    "CVE-2015-0318",
    "CVE-2015-0319",
    "CVE-2015-0320",
    "CVE-2015-0321",
    "CVE-2015-0322",
    "CVE-2015-0323",
    "CVE-2015-0324",
    "CVE-2015-0325",
    "CVE-2015-0326",
    "CVE-2015-0327",
    "CVE-2015-0328",
    "CVE-2015-0329",
    "CVE-2015-0330",
    "CVE-2015-0331"
  );
  script_bugtraq_id(72429, 72514, 72698);
  script_osvdb_id(
    117853,
    117967,
    117968,
    117969,
    117970,
    117971,
    117972,
    117973,
    117974,
    117975,
    117976,
    117977,
    117978,
    117979,
    117980,
    117981,
    117982,
    117983,
    118597
  );

  script_name(english:"Flash Player <= 16.0.0.296 Unspecified Code Execution (APSA15-02 / APSB15-04)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin that is affected by
multiple code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Adobe Flash Player installed on the
remote Windows host is equal or prior to 16.0.0.296. It is, therefore,
affected by the following vulnerabilities :

  - Several use-after-free errors exist that allow arbitrary
    code execution. (CVE-2015-0313, CVE-2015-0315,
    CVE-2015-0320, CVE-2015-0322)

  - Several memory corruption errors exist that allow
    arbitrary code execution. (CVE-2015-0314,
    CVE-2015-0316, CVE-2015-0318, CVE-2015-0321,
    CVE-2015-0329, CVE-2015-0330)

  - Several type confusion errors exist that allow
    arbitrary code execution. (CVE-2015-0317, CVE-2015-0319)

  - Several heap-based buffer-overflow errors exist that
    allow arbitrary code execution. (CVE-2015-0323,
    CVE-2015-0327)

  - A buffer overflow error exists that allows arbitrary
    code execution. (CVE-2015-0324)

  - Several null pointer dereference errors exist that have
    unspecified impacts. (CVE-2015-0325, CVE-2015-0326,
    CVE-2015-0328).

  - A user-after-free error exists within the processing of
    invalid m3u8 playlists. A remote attacker, with a
    specially crafted m3u8 playlist file, can force a
    dangling pointer to be reused after it has been freed,
    allowing the execution of arbitrary code.
    (CVE-2015-0331)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsa15-02.html");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-04.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-15-047/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 16.0.0.305 or later.

Alternatively, Adobe has made version 13.0.0.269 available for those
installations that cannot be upgraded to 16.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player PCRE Regex Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/02");

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
            # Chrome Flash <= 16.0.0.296
            variant == "Chrome_Pepper" &&
            (
              (iver[0] < 16) ||
              (iver[0] == 16 && iver[1] == 0 && iver[2] == 0 && iver[3] <= 296)
            )
          ) ||
          (variant != "Chrome_Pepper" &&
            (
             (
               # < 13
               (
                 iver[0] < 13 ||
                 # 13.0.0.x <= 13.0.0.264
                 (
                   iver[0] == 13 &&
                   (
                     iver[1] == 0 &&
                     (
                       iver[2] == 0 &&
                       (
                         iver[3] <= 264
                       )
                     )
                   )
                 )
               ) ||
               # 14.0.0.x <= 16.0.0.296
               (
                 iver[0] == 14 ||
                 (
                   iver[0] == 15 ||
                   (
                     iver[0] == 16 &&
                     (
                       iver[1] == 0 &&
                       (
                         iver[2] == 0 &&
                         (
                           iver[3] <= 296
                         )
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
            fix = "16.0.0.305 / 13.0.0.269";
          }
          else if (variant == "ActiveX")
          {
            info += '\n Product : ActiveX control (for Internet Explorer)';
            fix = "16.0.0.305 / 13.0.0.269";
          }
          else if ("Chrome" >< variant)
          {
            info += '\n Product : Browser Plugin (for Google Chrome)';
          }
          info += '\n  Path              : ' + file +
                  '\n  Installed version : ' + ver;
          if (variant == "Chrome_Pepper")
            info += '\n  Fixed version     : 16.0.0.305 (Chrome PepperFlash)';
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
