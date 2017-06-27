#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61622);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/20 14:02:59 $");

  script_cve_id(
    "CVE-2012-4163",
    "CVE-2012-4164",
    "CVE-2012-4165",
    "CVE-2012-4167",
    "CVE-2012-4168",
    "CVE-2012-4171",
    "CVE-2012-5054"
  );
  script_bugtraq_id(55365, 55691);
  script_osvdb_id(84789, 84790, 84791, 84792, 84793, 84794, 85260, 85786);

  script_name(english:"Flash Player <= 10.3.183.22 / 11.4.402.264 Multiple Vulnerabilities (APSB12-19)");
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
remote Windows host is 11.x equal to or earlier than 11.4.402.264, or
10.x equal to or earlier than 10.3.183.22.  It is, therefore,
potentially affected by multiple vulnerabilities :

  - Multiple memory corruption vulnerabilities could lead to
    code execution. (CVE-2012-4163, CVE-2012-4164,
    CVE-2012-4165)

  - An integer overflow vulnerability exists that could
    lead to code execution. (CVE-2012-4167)

  - A cross-domain information leak vulnerability exists.
    (CVE-2012-4168)

  - A crash can be caused by a logic error involving
    multiple dialogs in Firefox. (CVE-2012-4171)

  - A Matrix3D integer overflow vulnerability could lead
    to code execution. (CVE-2012-5054)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524143/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-19.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 10.3.183.23, 11.4.402.265 or
later, or Google Chrome PepperFlash 11.3.31.230 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/22");

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
                    (iver[2] == 31 && iver[3] <= 229)
                  )
                )
              )
            )
          ) ||
          (
            variant != "Chrome_Pepper" &&
            (
              # 10.x <= 10.3.183.22
              (
                iver[0] == 10 &&
                (
                  iver[1] < 3 ||
                  (
                    iver[1] == 3 &&
                    (
                      iver[2] < 183 ||
                      (iver[2] == 183 && iver[3] <= 22)
                    )
                  )
                )
              )
              ||
              # 11.x <= 11.4.402.264
              (
                iver[0] == 11 &&
                (
                  iver[1] < 4 ||
                  (
                    iver[1] == 4 &&
                    (
                      iver[2] < 402 ||
                      (iver[2] == 402 && iver[3] <= 264)
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
            info += '\n  Fixed version     : 11.3.31.230 (Chrome PepperFlash)';
          else
            info += '\n  Fixed version     : 10.3.183.23 / 11.4.402.265';
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
