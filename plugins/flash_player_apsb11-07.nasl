#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53472);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");
  
  script_cve_id("CVE-2011-0611");
  script_bugtraq_id(47314);
  script_osvdb_id(71686);
  script_xref(name:"CERT", value:"230057");
  script_xref(name:"Secunia", value:"44119");
  
  script_name(english:"Flash Player < 10.2.159.1 ActionScript Predefined Class Prototype Addition Remote Code Execution (APSB11-07)");
  script_summary(english:"Checks version of Flash Player");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser plug-in that allows
arbitrary code execution.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe Flash Player
earlier than 10.2.159.1.  Such versions are reportedly affected by a
memory corruption vulnerability. 

By tricking a user on the affected system into opening a specially
crafted document with Flash content, such as a SWF file embedded in a
Microsoft Word document, an attacker can potentially leverage this
issue to execute arbitrary code remotely on the system subject to the
user's privileges. 

Note that there are reports that this issue is being exploited in the
wild as of April 2011." );
 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ee82b34");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-07.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Flash Player 10.2.159.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player 10.2.153.1 SWF Memory Corruption Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value: "2011/04/11");
  script_set_attribute(attribute:"patch_publication_date", value: "2011/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/18");
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
          ("Plugin" >< variant || "ActiveX" >< variant) && (
            iver[0] < 10 ||
            (
              iver[0] == 10 &&
              (
                iver[1] < 2 ||
                (
                  iver[1] == 2 &&
                  (
                    iver[2] < 159 ||
                    (iver[2] == 159 && iver[3] < 1)
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
            info += '\n  Product : Browser Plugin (for Firefox / Netscape / Opera)';
          }
          else if (variant == "ActiveX")
          {
            info += '\n Product : ActiveX control (for Internet Explorer)';
          }

          info += '\n  Path              : ' + file +
                  '\n  Installed version : ' + ver +
                  '\n  Fixed version     : 10.2.159.1\n';
        }
        # Chrome
        else if (
          ("Chrome" >< variant) && (
            iver[0] < 10 ||
            (
              iver[0] == 10 &&
              (
                iver[1] < 2 ||
                (
                  iver[1] == 2 &&
                  (
                    iver[2] < 154 ||
                    (iver[2] == 154 && iver[3] < 27)
                  )
                )
              )
            )
          )
        )
        {
          num = key - ("SMB/Flash_Player/"+variant+"/Version/");
          file = files["SMB/Flash_Player/"+variant+"/File/"+num];
          info += '\n  Product: Browser Plugin (for Google Chrome)';
          info += '\n  Path              : ' + file +
                  '\n  Installed version : ' + ver ;
          info += '\n  Fixed version     : 10.2.154.27 (as included with Google Chrome 10.0.648.205)\n';
        }
      }
    }
  } 
}

if (info)
{
  if (report_verbosity > 0) security_hole(port:get_kb_item("SMB/transport"), extra:info);
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, 'The host is not affected.');
