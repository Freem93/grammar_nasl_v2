#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56874);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/05 16:01:14 $");

  script_cve_id(
    "CVE-2011-2445",
    "CVE-2011-2450",
    "CVE-2011-2451",
    "CVE-2011-2452",
    "CVE-2011-2453",
    "CVE-2011-2454",
    "CVE-2011-2455",
    "CVE-2011-2456",
    "CVE-2011-2457",
    "CVE-2011-2458",
    "CVE-2011-2459",
    "CVE-2011-2460"
  );
  script_bugtraq_id(
    50618,
    50619,
    50620,
    50621,
    50622,
    50623,
    50624,
    50625,
    50626,
    50627,
    50628,
    50629
  );
  script_osvdb_id(
    77018,
    77019,
    77020,
    77021,
    77022,
    77023,
    77024,
    77025,
    77026,
    77027,
    77028,
    77029
  );

  script_name(english:"Flash Player <= 10.3.183.10 / 11.0.1.152 Multiple Vulnerabilities (APSB11-28)");
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
"According to its version, the instance of Flash Player installed on
the remote Windows host is 10.x equal to or earlier than 10.3.183.10
or 11.x equal to or earlier than 11.0.1.152.  It is, therefore,
reportedly affected by several critical vulnerabilities :

  - Several unspecified memory corruption errors
    exist that could lead to code execution. 
    (CVE-2011-2445, CVE-2011-2451, CVE-2011-2452, 
    CVE-2011-2453, CVE-2011-2454, CVE-2011-2455, 
    CVE-2011-2459, CVE-2011-2460)

  - An unspecified heap corruption error exists that could
    lead to code execution. (CVE-2011-2450)

  - An unspecified buffer overflow error exists that could
    lead to code execution. (CVE-2011-2456)

  - An unspecified stack overflow error exists that could 
    lead to code execution. (CVE-2011-2457)

  - An unspecified error related to Internet Explorer can
    allow cross-domain policy violations. (CVE-2011-2458)"
  );

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-28.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash version 10.3.183.11 / 11.1.102.55 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Flash_Player/installed");

# Identify vulnerable versions.
info = "";

# nb: we're checking for versions less than *or equal to* the cutoff!
#     Cutoff here is  11.0.1.152; the next release was 11.1.102.55.
#     The same format was followed for 10.x - cutoff is 10.3.183.10;
#     the next release was 10.3.183.11.
foreach variant (make_list("Plugin", "ActiveX", "Chrome"))
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
          # <= 10.3.183.10
          iver[0] < 10 ||
          (
            iver[0] == 10 &&
            (
              iver[1] < 3 ||
              (
                iver[1] == 3 &&
                (
                  iver[2] < 183 ||
                  (iver[2] == 183 && iver[3] <= 10)
                )
              )
            )
          )
          ||
          (
            # 11.x <= 11.0.1.152
            iver[0] == 11 &&
            (
              iver[1] == 0 &&
              (
                iver[2] < 1 ||
                (iver[2] == 1 && iver[3] <= 152)
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
          else if (variant == "Chrome")
          {
            info += '\n Product : Browser Plugin (for Google Chrome)';
          }
          info += '\n  Path              : ' + file +
                  '\n  Installed version : ' + ver  +
                  '\n  Fixed version     : 10.3.183.11 / 11.1.102.55';
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
