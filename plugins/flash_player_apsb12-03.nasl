#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58001);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id(
    "CVE-2012-0751",
    "CVE-2012-0752",
    "CVE-2012-0753",
    "CVE-2012-0754",
    "CVE-2012-0755",
    "CVE-2012-0756",
    "CVE-2012-0767"
  );
  script_bugtraq_id(
    52032,
    52033,
    52034,
    52035,
    52036,
    52037,
    52040
  );
  script_xref(name:"EDB-ID", value:"18572");
  script_osvdb_id(
    79296,
    79297,
    79298,
    79299,
    79300,
    79301,
    79302
  );
  
  script_name(english:"Flash Player <= 10.3.183.14 / 11.1.102.55 Multiple Vulnerabilities (APSB12-03)");
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
the remote Windows host is 10.x equal to or earlier than 10.3.183.14
or 11.x equal to or earlier than 11.1.102.55.  It is, therefore,
reportedly affected by several critical vulnerabilities :

  - Multiple unspecified memory corruption issues exist that
    could lead to code execution. (CVE-2012-0751,
    CVE-2012-0754)

  - An unspecified type confusion memory corruption 
    vulnerability exists that could lead to code execution.
    (CVE-2012-0752)

  - An MP4 parsing memory corruption issue exists that
    could lead to code execution. (CVE-2012-0753)

  - Multiple unspecified security bypass vulnerabilities
    exist that could lead to code execution. (CVE-2012-0755,
    CVE-2012-0756)

  - A universal cross-site scripting issue exists that could
    be used to take actions on a user's behalf on any
    website or webmail provider. (CVE-2012-0767)"
  );

  # http://contagiodump.blogspot.com/2012/03/mar-2-cve-2012-0754-irans-oil-and.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2bd088e6");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-12-047/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-080/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Jun/67");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-03.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Flash version 10.3.183.15 / 11.1.102.62 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player MP4 \'cprt\' Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/17");

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

# nb: we're checking for versions less than *or equal to* the cutoff!
#     Cutoff here is  11.1.102.55; the next release was 11.1.102.62.
#     The same format was followed for 10.x - cutoff is 10.3.183.14;
#     the next release was 10.3.183.15.
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
          # 10.x <= 10.3.183.14
          iver[0] < 10 ||
          (
            iver[0] == 10 &&
            (
              iver[1] < 3 ||
              (
                iver[1] == 3 &&
                (
                  iver[2] < 183 ||
                  (iver[2] == 183 && iver[3] <= 14)
                )
              )
            )
          )
          ||
          (
            # 11.x <= 11.1.102.55
            iver[0] == 11 &&
            (
              iver[1] < 1 ||
              (
                iver[1] == 1 &&
                (
                  iver[2] < 102 ||
                  (iver[2] == 102 && iver[3] <= 55)
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
                  '\n  Fixed version     : 10.3.183.15 / 11.1.102.62';
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
