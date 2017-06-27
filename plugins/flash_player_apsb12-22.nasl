#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62480);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id(
    "CVE-2012-5248",
    "CVE-2012-5249",
    "CVE-2012-5250",
    "CVE-2012-5251",
    "CVE-2012-5252",
    "CVE-2012-5253",
    "CVE-2012-5254",
    "CVE-2012-5255",
    "CVE-2012-5256",
    "CVE-2012-5257",
    "CVE-2012-5258",
    "CVE-2012-5259",
    "CVE-2012-5260",
    "CVE-2012-5261",
    "CVE-2012-5262",
    "CVE-2012-5263",
    "CVE-2012-5264",
    "CVE-2012-5265",
    "CVE-2012-5266",
    "CVE-2012-5267",
    "CVE-2012-5268",
    "CVE-2012-5269",
    "CVE-2012-5270",
    "CVE-2012-5271",
    "CVE-2012-5272",
    "CVE-2012-5285",
    "CVE-2012-5286",
    "CVE-2012-5287",
    "CVE-2012-5673"
  );
  script_bugtraq_id(
    56198,
    56200,
    56201,
    56202,
    56203,
    56204,
    56205,
    56206,
    56207,
    56208,
    56209,
    56210,
    56211,
    56212,
    56213,
    56214,
    56215,
    56216,
    56217,
    56218,
    56219,
    56220,
    56221,
    56222,
    56224,
    56374,
    56375,
    56376,
    56377
  );
  script_osvdb_id(
    86025,
    86026,
    86027,
    86028,
    86029,
    86030,
    86031,
    86032,
    86033,
    86034,
    86035,
    86036,
    86037,
    86038,
    86039,
    86040,
    86041,
    86042,
    86043,
    86044,
    86045,
    86046,
    86047,
    86048,
    86049,
    86874,
    86875,
    86876,
    86877
  );

  script_name(english:"Flash Player <= 10.3.183.23 / 11.4.402.278 Multiple Vulnerabilities (APSB12-22)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a browser plugin that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Flash Player installed on the
remote Windows host is 11.x equal to or earlier than 11.4.402.278, or
10.x equal to or earlier than 10.3.183.23.  It is, therefore,
potentially affected by multiple vulnerabilities :

  - Several unspecified issues exist that can lead to buffer
    overflows and arbitrary code execution. (CVE-2012-5248,
    CVE-2012-5249, CVE-2012-5250, CVE-2012-5251,
    CVE-2012-5253, CVE-2012-5254, CVE-2012-5255,
    CVE-2012-5257, CVE-2012-5259, CVE-2012-5260,
    CVE-2012-5262, CVE-2012-5264, CVE-2012-5265,
    CVE-2012-5266, CVE-2012-5285, CVE-2012-5286,
    CVE-2012-5287)

  - Several unspecified issues exist that can lead to memory
    corruption and arbitrary code execution. (CVE-2012-5252,
    CVE-2012-5256, CVE-2012-5258, CVE-2012-5261,
    CVE-2012-5263, CVE-2012-5267, CVE-2012-5268,
    CVE-2012-5269, CVE-2012-5270, CVE-2012-5271,
    CVE-2012-5272)

  - An unspecified issue exists having unspecified impact.
    (CVE-2012-5673)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-22.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 10.3.183.29, 11.4.402.287 or
later, or Google Chrome PepperFlash 11.4.31.110 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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
            variant == "Chrome_Pepper" &&
            (
              iver[0] == 11 &&
              (
                iver[1] < 3 ||
                (
                  iver[1] == 3 &&
                  (
                    iver[2] < 31 ||
                    (iver[2] == 31 && iver[3] <= 331)
                  )
                )
              )
            )
          ) ||
          (
            variant != "Chrome_Pepper" &&
            (
              # 10.x <= 10.3.183.23
              (
                iver[0] == 10 &&
                (
                  iver[1] < 3 ||
                  (
                    iver[1] == 3 &&
                    (
                      iver[2] < 183 ||
                      (iver[2] == 183 && iver[3] <= 23)
                    )
                  )
                )
              ) 
              ||
              # 11.x <= 11.4.402.278
              (
                iver[0] == 11 &&
                (
                  iver[1] < 4 ||
                  (
                    iver[1] == 4 &&
                    (
                      iver[2] < 402 ||
                      (iver[2] == 402 && iver[3] <= 278)
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
            info += '\n  Fixed version     : 11.4.31.110 (Chrome PepperFlash)';
          else
            info += '\n  Fixed version     : 10.3.183.29 / 11.4.402.287';
          info += '\n';
        }
      }
    }
  }
}

if (info)
{
  if (report_verbosity > 0)
    security_hole(port:get_kb_item("SMB/transport"), extra:info);
  else
    security_hole(get_kb_item("SMB/transport"));
}
else
{ 
  if (thorough_tests) 
    exit(0, 'No vulnerable versions of Adobe Flash Player were found.');
  else
    exit(1, 'Google Chrome\'s built-in Flash Player may not have been detected because the \'Perform thorough tests\' setting was not enabled.');
}
