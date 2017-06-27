#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62836);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/05 16:01:15 $");

  script_cve_id(
    "CVE-2012-5274",
    "CVE-2012-5275",
    "CVE-2012-5276",
    "CVE-2012-5277",
    "CVE-2012-5278",
    "CVE-2012-5279",
    "CVE-2012-5280"
  );
  script_bugtraq_id(56542, 56543, 56544, 56545, 56546, 56547, 56554);
  script_osvdb_id( 87064, 87065, 87066, 87067, 87068, 87069, 87070);

  script_name(english:"Flash Player <= 10.3.183.29 / 11.4.402.287 Multiple Vulnerabilities (APSB12-24)");
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
remote Windows host is 11.x equal to or earlier than 11.4.402.287, or
10.x equal to or earlier than 10.3.183.29.  It is, therefore,
potentially affected by multiple vulnerabilities :

  - Several unspecified issues exist that can lead to buffer
    overflows and arbitrary code execution. (CVE-2012-5274,
    CVE-2012-5275, CVE-2012-5276, CVE-2012-5277,
    CVE-2012-5280)

  - An unspecified security bypass issue exists that can
    lead to arbitrary code execution. (CVE-2012-5278)

  - An unspecified issue exists that can lead to memory
    corruption and arbitrary code execution. (CVE-2012-5279)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-24.html");
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to Adobe Flash Player version 10.3.183.43, 11.5.502.110 or
later, or Google Chrome PepperFlash 11.5.31.2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/07");

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
            # Chrome Flash <= 11.4.402.287
            variant == "Chrome_Pepper" &&
            (
              iver[0] == 11 &&
              (
                iver[1] < 4 ||
                (
                  iver[1] == 4 &&
                  (
                    iver[2] < 402 ||
                    (iver[2] == 402 && iver[3] <= 287)
                  )
                )
              )
            )
          ) ||
          (
            variant != "Chrome_Pepper" &&
            (
              # 10.x <= 10.3.183.29
              (
                iver[0] == 10 &&
                (
                  iver[1] < 3 ||
                  (
                    iver[1] == 3 &&
                    (
                      iver[2] < 183 ||
                      (iver[2] == 183 && iver[3] <= 29)
                    )
                  )
                )
              ) 
              ||
              # 11.x <= 11.4.402.287
              (
                iver[0] == 11 &&
                (
                  iver[1] < 4 ||
                  (
                    iver[1] == 4 &&
                    (
                      iver[2] < 402 ||
                      (iver[2] == 402 && iver[3] <= 287)
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
            info += '\n  Fixed version     : 11.5.31.2 (Chrome PepperFlash)';
          else
            info += '\n  Fixed version     : 10.3.183.43 / 11.5.502.110';
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
