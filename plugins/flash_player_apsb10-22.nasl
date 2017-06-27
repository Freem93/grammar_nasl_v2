#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49307);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id("CVE-2010-2884");
  script_bugtraq_id(43205);
  script_osvdb_id(68024);
  script_xref(name:"CERT", value:"275289");

  script_name(english:"Flash Player < 9.0.283 / 10.1.85.3 Unspecified Code Execution (APSB10-22)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser plug-in that is affected
by a code execution vulnerability."
  );
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe Flash Player 9.x
before 9.0.283 or 10.x earlier than 10.1.85.3.  Such versions are
potentially affected by an unspecified code execution vulnerability. 

Note that there are reports this is being actively exploited in the 
wild.");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-22.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Flash Player 10.1.85.3 / 9.0.283 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"vuln_publication_date",value:"2010/09/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/21");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


get_kb_item_or_exit('SMB/Flash_Player/installed');

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
        for(i=0;i<max_index(iver);i++)
          iver[i] = int(iver[i]);
  
        if (
          # nb: versions before 9.0 are not affected.
          # Chrome never shipped with Flash Player < 10.x
          (
            (iver[0] == 9 && iver[1] == 0 && iver[2] < 283) &&
            (variant == "Plugin" || variant == "ActiveX")
          ) ||
          (
            iver[0] == 10 &&
            (
              iver[1] < 1 ||
              (
                iver[1] == 1 &&
                (
                  iver[2] < 85 ||
                  (iver[2] == 85 && iver[3] < 3)
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
            info += '\n  Product : Browser Plugin (for Firefox / Netscape / Opera)';
          }
          else if (variant == "ActiveX")
          {
            info += '\n  Product : ActiveX control (for Internet Explorer)';
          }
          else if (variant == "Chrome")
          {
            info += '\n  Product : Browser Plugin (for Google Chrome)';
          }
          
          info += '\n  Path              : ' + file +
                  '\n  Installed version : ' + ver;
 
          if (variant == "Plugin" || variant == "ActiveX")
          { 
            if (iver[0] == 9)       info += '\n  Fixed version     : 9.0.283';
            else if (iver[0] == 10) info += '\n  Fixed version     : 10.1.85.3';
          }

          if (variant == "Chrome")
            info += '\n  Fixed version     : 10.1.85.3 (as included with Google Chrome 6.0.472.62)';

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
else exit(0, 'The host is not affected.');
