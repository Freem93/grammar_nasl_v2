#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51926);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/20 14:02:59 $");

  script_cve_id("CVE-2011-0558", "CVE-2011-0559", "CVE-2011-0560", "CVE-2011-0561",
                "CVE-2011-0571", "CVE-2011-0572", "CVE-2011-0573", "CVE-2011-0574",
                "CVE-2011-0575", "CVE-2011-0577", "CVE-2011-0578", "CVE-2011-0607",
                "CVE-2011-0608");
  script_bugtraq_id(46186, 46188, 46189, 46190, 46191, 46192, 46193, 46194, 46195,
                    46196, 46197, 46282, 46283);
  script_osvdb_id(
    70911,
    70913,
    70914,
    70915,
    70916,
    70917,
    70918,
    70919,
    70920,
    70921,
    70922,
    70923,
    70976
  );

  script_name(english:"Flash Player < 10.2.152.26 Multiple Vulnerabilities (APSB11-02)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser plug-in that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe Flash Player
earlier than 10.2.152.26.  Such versions are potentially affected by
multiple vulnerabilities :

  - An integer overflow exists that could lead to code
    execution. (CVE-2011-0558)

  - Multiple memory corruption vulnerabilities exist that 
    could lead to code execution. (CVE-2011-0559,
    CVE-2011-0560, CVE-2011-0561, CVE-2011-0571, 
    CVE-2011-0572, CVE-2011-0573, CVE-2011-0574, 
    CVE-2011-0578, CVE-2011-0607, CVE-2011-0608)

  - A library-loading vulnerability exists that could lead
    to code execution. (CVE-2011-0575)

  - A font-parsing vulnerability exists that could lead to
    code execution. (CVE-2011-0577)");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-02.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Flash Player 10.2.152.26 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2011/02/08");
  script_set_attribute(attribute:"patch_publication_date",value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/09");
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


get_kb_item_or_exit('SMB/Flash_Player/installed');

info = '';

foreach variant (make_list("Plugin", "ActiveX"))
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
          iver[0] < 10 ||
          (
            iver[0] == 10 &&
            (
              iver[1] < 2 ||
              (
                iver[1] == 2 &&
                (
                  iver[2] < 152 ||
                  (iver[2] == 152 && iver[3] < 26)
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
                  '\n  Installed version : ' + ver +
                  '\n  Fixed version     : 10.2.152.26\n';
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
