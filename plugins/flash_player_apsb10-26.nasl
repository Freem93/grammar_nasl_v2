#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50493);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id("CVE-2010-3636", "CVE-2010-3637", "CVE-2010-3639", "CVE-2010-3640",
                "CVE-2010-3641", "CVE-2010-3642", "CVE-2010-3643", "CVE-2010-3644", 
                "CVE-2010-3645", "CVE-2010-3646", "CVE-2010-3647", "CVE-2010-3648",
                "CVE-2010-3649", "CVE-2010-3650", "CVE-2010-3652", "CVE-2010-3654", 
                "CVE-2010-3976");
  script_bugtraq_id(44504, 44671, 44691, 44692);
  script_osvdb_id(
    68736,
    68932,
    69121,
    69122,
    69123,
    69124,
    69125,
    69126,
    69127,
    69128,
    69129,
    69130,
    69131,
    69132,
    69133,
    69135,
    69146
  );
  script_xref(name:"CERT", value:"298081");
  script_xref(name:"Secunia", value:"41917");

  script_name(english:"Flash Player < 9.0.289 / 10.1.102.64 Multiple Vulnerabilities (APSB10-26)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser plug-in that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe Flash Player 9.x
before 9.0.289 or 10.x earlier than 10.1.102.64.  Such versions are
potentially affected by multiple vulnerabilities :

  - A memory corruption vulnerability exists that could lead
    to code execution.  Note that there are reports that 
    this is being actively exploited in the wild. 
    (CVE-2010-3654)

  - An input validation issue exists that could lead to a
    bypass of cross-domain policy file restrictions with
    certain server encodings. (CVE-2010-3636)

  - A memory corruption vulnerability exists in the ActiveX
    component. (CVE-2010-3637)

  - An unspecified issue exists which could lead to a 
    denial of service or potentially arbitrary code 
    execution. (CVE-2010-3639)

  - Multiple memory corruption issues exist that could lead
    to arbitrary code execution. (CVE-2010-3640, 
    CVE-2010-3641, CVE-2010-3642, CVE-2010-3643, 
    CVE-2010-3644, CVE-2010-3645, CVE-2010-3646,
    CVE-2010-3647, CVE-2010-3648, CVE-2010-3649,
    CVE-2010-3650, CVE-2010-3652)
    
  - A library-loading vulnerability could lead to code 
    execution. (CVE-2010-3976)");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-26.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Flash Player 10.1.102.64 / 9.0.289 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player "Button" Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date",value:"2010/09/10");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/05");
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
            ("Plugin" >< variant || "ActiveX" >< variant) &&
            (
              # nb: versions before 9.0 are not affected.
              (iver[0] == 9 && iver[1] == 0 && iver[2] < 289) ||
              (
                iver[0] == 10 &&
                (
                  iver[1] < 1 ||
                  (
                    iver[1] == 1 &&
                    (
                      iver[2] < 102 ||
                      (iver[2] == 102 && iver[3] < 64)
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
            info += '\n  Product : ActiveX control (for Internet Explorer)';
          }
          
          info += '\n  Path              : ' + file +
                  '\n  Installed version : ' + ver;
  
          if (iver[0] == 9)       info += '\n  Fixed version     : 9.0.289\n';
          else if (iver[0] == 10) info += '\n  Fixed version     : 10.1.102.64\n';
        }
        else if (
           ("Chrome" >< variant) && (
            iver[0] < 10 ||
            (
              iver[0] == 10 &&
              (
                iver[1] < 1 ||
                (
                  iver[1] == 1 &&
                  (
                    iver[2] < 103 ||
                    (iver[2] == 103 && iver[3] < 19)
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
          info += '\n  Fixed version     : 10.1.103.19 (as included with Google Chrome 7.0.517.44)\n';
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
