#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55803);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/20 14:02:59 $");

  script_cve_id(
    "CVE-2011-2130",
    "CVE-2011-2134",
    "CVE-2011-2135",
    "CVE-2011-2136",
    "CVE-2011-2137",
    "CVE-2011-2138",
    "CVE-2011-2139",
    "CVE-2011-2140",
    "CVE-2011-2414",
    "CVE-2011-2415",
    "CVE-2011-2416",
    "CVE-2011-2417",
    "CVE-2011-2424",
    "CVE-2011-2425"
  );
  script_bugtraq_id(
    49073,
    49074,
    49075,
    49076,
    49077,
    49079,
    49080,
    49081,
    49082,
    49083,
    49084,
    49085,
    49086,
    49186
  );
  script_osvdb_id(
    74432,
    74433,
    74434,
    74435,
    74436,
    74437,
    74438,
    74439,
    74440,
    74441,
    74442,
    74443,
    74444,
    75201
  );
  script_xref(name:"EDB-ID", value:"18437");
  script_xref(name:"EDB-ID", value:"18479");

  script_name(english:"Flash Player <= 10.3.181.36 Multiple Vulnerabilities (APSB11-21)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(attribute:"synopsis", value:
"A browser plugin is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Flash Player installed on
the remote Windows host is 10.3.181.36 or earlier.  As such, it is
reportedly affected by several critical vulnerabilities :

  - Multiple buffer overflow vulnerabilities could lead to
    code execution. (CVE-2011-2130, CVE-2011-2134, 
    CVE-2011-2137, CVE-2011-2414, CVE-2011-2415)

  - Multiple memory corruption vulnerabilities could lead to
    code execution. (CVE-2011-2135, CVE-2011-2140, 
    CVE-2011-2417, CVE-2011-2424, CVE-2011-2425)

  - Multiple integer overflow vulnerabilities could lead to
    code execution. (CVE-2011-2136, CVE-2011-2138, 
    CVE-2011-2416)

  - A cross-site information disclosure vulnerability 
    exists that could lead to code execution. 
    (CVE-2011-2139)

By tricking a user on the affected system into opening a specially
crafted document with Flash content, an attacker could leverage these
vulnerabilities to execute arbitrary code remotely on the system
subject to the user's privileges.");

  # idefense advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18dbdb20");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0651458a");
  # http://www.abysssec.com/blog/2012/01/31/exploiting-cve-2011-2140-another-flash-player-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46d1fce8");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-253/");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-21.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Flash version 10.3.183.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player MP4 SequenceParameterSetNALUnit Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/10");

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
          iver[0] < 10 ||
          (
            iver[0] == 10 &&
            (
              iver[1] < 3 ||
              (
                iver[1] == 3 &&
                (
                  iver[2] < 181 ||
                  (iver[2] == 181 && iver[3] <= 36)
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
                  '\n  Fixed version     : 10.3.183.5';
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
