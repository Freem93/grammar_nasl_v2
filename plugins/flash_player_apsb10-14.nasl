#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(46859);
  script_version("$Revision: 1.54 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id("CVE-2008-4546", "CVE-2009-3793", "CVE-2010-1297", "CVE-2010-2160", "CVE-2010-2161",
                "CVE-2010-2162", "CVE-2010-2163", "CVE-2010-2164", "CVE-2010-2165", "CVE-2010-2166",
                "CVE-2010-2167", "CVE-2010-2169", "CVE-2010-2170", "CVE-2010-2171", "CVE-2010-2172",
                "CVE-2010-2173", "CVE-2010-2174", "CVE-2010-2175", "CVE-2010-2176", "CVE-2010-2177",
                "CVE-2010-2178", "CVE-2010-2179", "CVE-2010-2180", "CVE-2010-2181", "CVE-2010-2182",
                "CVE-2010-2183", "CVE-2010-2184", "CVE-2010-2185", "CVE-2010-2186", "CVE-2010-2187",
                # "CVE-2010-2188",     # nb: Adobe removed this from APSB10-14.
                "CVE-2010-2189");
  script_bugtraq_id(31537, 40586, 40779, 40780, 40781, 40782, 40783, 40784, 40785,
                    40786, 40787, 40788, 40789, 40790, 40791, 40792, 40793, 40794,
                    40795, 40796, 40797,
                    # 40798,     # nb: Adobe removed this from APSB10-14.
                    40799, 40800, 40801, 40802, 40803, 40805, 40806, 40807, 40808, 40809);
  script_osvdb_id(
    50073,
    65141,
    65532,
    65572,
    65573,
    65574,
    65575,
    65576,
    65577,
    65578,
    65579,
    65580,
    65581,
    65582,
    65583,
    65584,
    65585,
    65586,
    65587,
    65588,
    65589,
    65590,
    65591,
    65592,
    65593,
    65594,
    65595,
    65596,
    65597,
    65598,
    65600,
    66119
  );
  script_xref(name:"CERT", value:"486225");
  script_xref(name:"Secunia", value:"40026");

  script_name(english:"Flash Player < 9.0.277.0 / 10.1.53.63 Multiple Vulnerabilities (ASPB10-14)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser plug-in that is affected
by a code execution vulnerability."
  );
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe Flash Player 9.x
before 9.0.277.0 or 10.x before 10.1.53.63.  Such versions are
affected by multiple vulnerabilities, such as memory corruption,
buffer overflows, and memory exhaustion, that could be exploited to
cause an application crash or even allow execution of arbitrary
code.");
  
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-14.html");
  script_set_attribute(attribute:"solution",value:
"Upgrade to Flash Player 10.1.53.64 / 9.0.277.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-164");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player "newfunction" Invalid Pointer Use');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(399);
  script_set_attribute(attribute:"vuln_publication_date",value:"2008/10/01");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/06/10");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/06/10");
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

if (!get_kb_item("SMB/Flash_Player/installed")) exit(1, "The 'SMB/Flash_Player/installed' KB item is missing.");

include("global_settings.inc");

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
            (iver[0] == 9 && iver[1] == 0 && iver[2] < 277) &&
            (variant == "Plugin" || variant == "ActiveX")
          ) ||
          (
            iver[0] == 10 && 
            (
              iver[1] < 1 ||
              (
                iver[1] == 1 &&
                (
                  iver[2] < 53 ||
                  (iver[2] == 53 && iver[3] < 64)
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
            if (iver[0] == 9)       info += '\n  Fixed version     : 9.0.277.0';
            else if (iver[0] == 10) info += '\n  Fixed version     : 10.1.53.64';
          }

          if (variant == "Chrome")
            info += '\n  Fixed version     : 10.1.53.64 (as included with Google Chrome 5.0.375.125)';

          info += '\n';

        }
      }
    }
  }
}

if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 2)
      inst = "s";
    else
      inst = "";

    report = 
      '\n' +
      'Nessus has identified the following vulnerable instance' + inst + ' of Flash\n' +
      'Player installed on the remote host :\n' +
      '\n'+
      info;
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, 'The host is not affected.');
