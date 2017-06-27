#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73740);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2014-0515");
  script_bugtraq_id(67092);
  script_osvdb_id(106347);

  script_name(english:"Flash Player <= 11.7.700.275 / 13.0.0.182 Pixel Bender Component Buffer Overflow (APSB14-13)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin that is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Flash Player installed on
the remote Windows host is equal or prior to 11.7.700.275 / 11.8.x /
11.9.x / 12.x / 13.0.0.182. It is, therefore, potentially affected by
a buffer overflow vulnerability due to improper user input validation
in the Pixel Bender component. An attacker could cause a buffer
overflow with a specially crafted SWF file, resulting in arbitrary
code execution.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-13.html");
  # https://www.securelist.com/en/blog/8212/New_Flash_Player_0_day_CVE_2014_0515_used_in_watering_hole_attacks
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5043fc7b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 11.7.700.279 / 13.0.0.206 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Shader Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/28");

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
            # Chrome Flash <= 13.0.0.182
            variant == "Chrome_Pepper" &&
            (iver[0] == 13 && iver[1] == 0 && iver[2] == 0 && iver[3] <= 182)
          ) ||
          (variant != "Chrome_Pepper" &&
            (
             # < 11
             iver[0] < 11 ||
             # 11.x <= 11.7.700.275
             (
               iver[0] == 11 &&
               (
                 iver[1] < 7 ||
                 (
                   iver[1] == 7 &&
                   (
                     iver[2] < 700 ||
                     (iver[2] == 700 && iver[3] <= 275)
                   )
                 )
               )
             ) ||
             # 11.8.x
             (iver[0] == 11 && iver[1] == 8) ||
             # 11.9.x
             (iver[0] == 11 && iver[1] == 9) ||
             # 12.x
             (iver[0] == 12) ||

             # 13.0.0.x <= 13.0.0.182
             (
               iver[0] == 13 &&
               (
                 iver[1] == 0 &&
                 (
                   iver[2] == 0 &&
                   (
                     iver[3] <= 182
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
            info += '\n  Product: Browser Plugin (for Firefox / Netscape / Opera)';
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
            info += '\n  Fixed version     : 13.0.0.206 (Chrome PepperFlash)';
          else
          {
            if (ver =~ "^11\.7")
              fix = "11.7.700.279";
            else
              fix = "13.0.0.206";
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
