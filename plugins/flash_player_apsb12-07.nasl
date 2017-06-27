#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58538);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/05 16:01:15 $");

  script_cve_id(
    "CVE-2012-0772", 
    "CVE-2012-0773", 
    "CVE-2012-0724", 
    "CVE-2012-0725"
  );
  script_bugtraq_id(52748, 52914, 52916);
  script_osvdb_id(80706, 80707, 81244, 81245);

  script_name(english:"Flash Player <= 10.3.183.16 / 11.1.102.63 Multiple Memory Corruption Vulnerabilities (APSB12-07)");
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
"According to its version, the instance of Flash Player installed on
the remote Windows host is 10.x equal to or earlier than 10.3.183.16
or 11.x equal to or earlier than 11.1.102.63.  It is, therefore,
reportedly affected by several critical memory corruption
vulnerabilities :

  - Memory corruption vulnerabilities related to URL 
    security domain checking. (CVE-2012-0772)

  - A flaw in the NetStream Class that could lead to remote
    code execution. (CVE-2012-0773)

  - Two Flash Player memory corruption vulnerabilities
    related to the Google Chrome interface. 
    (CVE-2012-0724, CVE-2012-0725)  

By tricking a victim into visiting a specially crafted page, an
attacker may be able to utilize these vulnerabilities to execute
arbitrary code subject to the users' privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-057/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/522413/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-07.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Adobe Flash version 11.2.202.228 / 10.3.183.18 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/30");

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
          # 10.x <= 10.3.183.16
          (
            iver[0] == 10 &&
            (
              iver[1] < 3 ||
              (
                iver[1] == 3 &&
                (
                  iver[2] < 183 ||
                  (iver[2] == 183 && iver[3] <= 16)
                )
              )
            )
          )
          ||
          (
            # 11.x <= 11.1.102.63
            iver[0] == 11 &&
            (
              iver[1] < 1 ||
              (
                iver[1] == 1 &&
                (
                  iver[2] < 102 ||
                  (iver[2] == 102 && iver[3] <= 63)
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
          else if (variant == "Chrome")
          {
            info += '\n Product : Browser Plugin (for Google Chrome)';
          }
          info += '\n  Path              : ' + file +
                  '\n  Installed version : ' + ver  +
                  '\n  Fixed version     : 11.2.202.228 / 10.3.183.18';
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
