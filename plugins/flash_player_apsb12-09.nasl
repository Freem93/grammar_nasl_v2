#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58994);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id("CVE-2012-0779");
  script_bugtraq_id(53395);
  script_osvdb_id(81656);

  script_name(english:"Flash Player <= 10.3.183.18 / 11.2.202.233 Object Confusion Vulnerability (APSB12-09)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a browser plugin that is affected by a
code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the instance of Flash Player installed on
the remote Windows host is 10.x equal to or earlier than 10.3.183.18
or 11.x equal to or earlier than 11.2.202.233.  It is, therefore,
reportedly affected by an object confusion vulnerability that could
allow an attacker to crash the application or potentially take control
of the target system. 

By tricking a victim into visiting a specially crafted page, an
attacker may be able to utilize this vulnerability to execute
arbitrary code subject to the users' privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-09.html");
  #http://blogs.technet.com/b/mmpc/archive/2012/05/24/a-technical-analysis-of-adobe-flash-player-cve-2012-0779-vulnerability.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba4bc112");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Adobe Flash Player version 10.3.183.19 / 11.2.202.235 or
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player Object Type Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/04");

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
          # 10.x <= 10.3.183.18
          (
            iver[0] == 10 &&
            (
              iver[1] < 3 ||
              (
                iver[1] == 3 &&
                (
                  iver[2] < 183 ||
                  (iver[2] == 183 && iver[3] <= 18)
                )
              )
            )
          )
          ||
          (
            # 11.x <= 11.2.202.233
            iver[0] == 11 &&
            (
              iver[1] < 2 ||
              (
                iver[1] == 2 &&
                (
                  iver[2] < 202 ||
                  (iver[2] == 202 && iver[3] <= 233)
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
                  '\n  Fixed version     : 10.3.183.19 / 11.2.202.235';
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
