#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69866);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/13 15:19:32 $");

  script_cve_id(
    "CVE-2013-3361",
    "CVE-2013-3362",
    "CVE-2013-3363",
    "CVE-2013-5324"
  );
  script_bugtraq_id(62290, 62294, 62295, 62296);
  script_osvdb_id(97050, 97051, 97052, 97053);

  script_name(english:"Flash Player <= 11.7.700.232 / 11.8.800.94 Memory Corruptions (APSB13-21)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a browser plugin that is affected by
multiple memory corruption vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Flash Player installed on the
remote Windows host is equal or prior to 10.3.183.90 / 11.x equal or
prior to 11.7.700.232 / 11.8.x equal or prior to 11.8.800.94.  It is,
therefore, potentially affected by multiple memory corruption
vulnerabilities that could lead to code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-21.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Adobe Flash Player version 11.7.700.242 / 11.8.800.168 or
later, or Google Chrome Flash 11.8.800.170 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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
            # Chrome Flash <= 11.8.800.97
            variant == "Chrome_Pepper" &&
            (
              iver[0] == 11 &&
              (
                iver[1] < 8 ||
                (
                  iver[1] == 8 &&
                  (
                    iver[2] < 800 ||
                    (iver[2] == 800 && iver[3] <= 97)
                  )
                )
              )
            )
          ) ||
          (variant != "Chrome_Pepper" &&
            (
             # 10.x <= 10.3.183.90
              (
                (iver[0] < 10) || (iver[0] == 10 &&
                  (
                    iver[1] < 3 ||
                    (
                      iver[1] == 3 &&
                      (
                        iver[2] < 183 ||
                       (iver[2] == 183 && iver[3] <= 90)
                      )
                    )
                  )
                )
              ) || 
             # 11.x <= 11.7.700.232
             (
               iver[0] == 11 &&
               (
                 iver[1] < 7 ||
                 (
                   iver[1] == 7 &&
                   (
                     iver[2] < 700 ||
                     (iver[2] == 700 && iver[3] <= 232)
                   )
                 )
               )
             ) ||
             # 11.8.x <= 11.8.800.94
             (
               iver[0] == 11 &&
               (
                 iver[1] == 8 &&
                 (
                   iver[2] < 800 ||
                   (iver[2] == 800 && iver[3] <= 94)
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
            info += '\n  Fixed version     : 11.8.800.170 (Chrome PepperFlash)';
 	  else
            info += '\n  Fixed version     : 11.7.700.242 / 11.8.800.168';
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
