#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77577);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id(
    "CVE-2014-0547",
    "CVE-2014-0548",
    "CVE-2014-0549",
    "CVE-2014-0550",
    "CVE-2014-0551",
    "CVE-2014-0552",
    "CVE-2014-0553",
    "CVE-2014-0554",
    "CVE-2014-0555",
    "CVE-2014-0556",
    "CVE-2014-0557",
    "CVE-2014-0559"
  );
    script_bugtraq_id(
    69695,
    69696,
    69697,
    69699,
    69700,
    69701,
    69702,
    69703,
    69704,
    69705,
    69706,
    69707
  );
  script_osvdb_id(
    111100,
    111101,
    111102,
    111103,
    111104,
    111105,
    111106,
    111107,
    111108,
    111109,
    111110,
    111111
  );

  script_name(english:"Flash Player <= 14.0.0.179 Multiple Vulnerabilities (APSB14-21)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Flash Player installed
on the remote Windows host is equal or prior to 14.0.0.179. It is,
therefore, affected by the following vulnerabilities :

  - Unspecified memory corruption issues exist that allow
    arbitrary code execution. (CVE-2014-0547, CVE-2014-0549,
    CVE-2014-0550, CVE-2014-0551, CVE-2014-0552,
    CVE-2014-0555)

  - An unspecified error exists that allows cross-origin
    policy violations. (CVE-2014-0548)

  - A use-after-free error exists that allows arbitrary
    code execution. (CVE-2014-0553)

  - An unspecified error exists that allows an unspecified
    security bypass. (CVE-2014-0554)

  - Unspecified errors exist that allow memory leaks leading
    to easier defeat of memory address randomization.
    (CVE-2014-0557)

  - Heap-based buffer overflow errors exist that allow
    arbitrary code execution. (CVE-2014-0556, CVE-2014-0559)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-21.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 15.0.0.152 or later.

Alternatively, Adobe has made version 13.0.0.244 available for those
installations that cannot be upgraded to 15.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player copyPixelsToByteArray Method Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/10");

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
            # Chrome Flash <= 14.0.0.177
            variant == "Chrome_Pepper" &&
            (iver[0] == 14 && iver[1] == 0 && iver[2] == 0 && iver[3] <= 177)
          ) ||
          (variant != "Chrome_Pepper" &&
            (
             (
               # < 13
               (
                 iver[0] < 13 ||
                 # 13.0.0.x <= 13.0.0.241
                 (
                   iver[0] == 13 &&
                   (
                     iver[1] == 0 &&
                     (
                       iver[2] == 0 &&
                       (
                         iver[3] <= 241
                       )
                     )
                   )
                 )
               ) ||
               # 14.0.0.x <= 14.0.0.179
               (
                 iver[0] == 14 &&
                 (
                   iver[1] == 0 &&
                   (
                     iver[2] == 0 &&
                     (
                       iver[3] <= 179
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
            fix = "15.0.0.152 / 13.0.0.244";
          }
          else if (variant == "ActiveX")
          {
            info += '\n Product : ActiveX control (for Internet Explorer)';
            fix = "15.0.0.152 / 13.0.0.244";
          }
          else if ("Chrome" >< variant)
          {
            info += '\n Product : Browser Plugin (for Google Chrome)';
          }
          info += '\n  Path              : ' + file +
                  '\n  Installed version : ' + ver;
          if (variant == "Chrome_Pepper")
            info += '\n  Fixed version     : 15.0.0.152 (Chrome PepperFlash)';
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
