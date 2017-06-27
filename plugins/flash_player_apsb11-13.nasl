#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54972);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/06/14 17:29:37 $");
  
  script_cve_id("CVE-2011-2107");
  script_bugtraq_id(48107);
  script_osvdb_id(72723);
  script_xref(name:"Secunia", value:"44846");
  
  script_name(english:"Flash Player < 10.3.181.22 XSS (APSB11-13)");
  script_summary(english:"Checks version of Flash Player");
 
  script_set_attribute(attribute:"synopsis", value:
"A browser plugin is affected by a cross-scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"An unspecified cross-site scripting vulnerability exists in versions
of Flash Player earlier than 10.3.181.22 (10.3.181.23 for ActiveX). 

An attacker may be able to leverage this issue to inject and execute
arbitrary HTML and script code in a user's browser.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-13.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Flash version 10.3.181.22 (10.3.181.23 for ActiveX) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value: "2011/06/05");
  script_set_attribute(attribute:"patch_publication_date", value: "2011/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/06");

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

include('global_settings.inc');
include('misc_func.inc');

get_kb_item_or_exit('SMB/Flash_Player/installed');

# Identify vulnerable versions.
info = '';

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
          (
            (variant == "Plugin" || variant == "Chrome") &&
            (
              iver[0] < 10 ||
              (
                iver[0] == 10 &&
                (
                  iver[1] < 3 ||
                  (
                    iver[1] == 3 &&
                    (
                      iver[2] < 181 ||
                      (iver[2] == 181 && iver[3] < 22)
                    )
                  )
                )
              )
            )
          ) ||
          (
            (variant == "ActiveX") &&
            (
              iver[0] < 10 ||
              (
                iver[0] == 10 &&
                (
                  iver[1] < 3 ||
                  (
                    iver[1] == 3 &&
                    (
                      iver[2] < 181 ||
                      (iver[2] == 181 && iver[3] < 23)
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
          else if (variant == "Chrome")
          {
            info += '\n Product : Browser Plugin (for Google Chrome)';
          }
          
          if (variant == "Plugin" || variant == "Chrome")
          {
            info += '\n  Path              : ' + file +
                    '\n  Installed version : ' + ver  +
                    '\n  Fixed version     : 10.3.181.22';
          }
          if (variant == "Chrome")
            info += ' (as included with Google Chrome 11.0.696.77)';

          if (variant == "ActiveX")
          {
            info += '\n Product : ActiveX control (for Internet Explorer)';
            info += '\n  Path              : ' + file +
                    '\n  Installed version : ' + ver  +
                    '\n  Fixed version     : 10.3.181.23';
          }

          info += '\n';
        }
      }
    }
  } 
}

if (info)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
  if (report_verbosity > 0)
    security_warning(port:get_kb_item("SMB/transport"), extra:info);
  else
    security_warning(get_kb_item("SMB/transport"));
}
else exit(0, 'The host is not affected.');
