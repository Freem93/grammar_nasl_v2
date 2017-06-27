#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74431);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id(
    "CVE-2014-0531",
    "CVE-2014-0532",
    "CVE-2014-0533",
    "CVE-2014-0534",
    "CVE-2014-0535",
    "CVE-2014-0536"
  );
  script_bugtraq_id(67961, 67962, 67963, 67970, 67973, 67974);
  script_osvdb_id(107822, 107823, 107824, 107825, 107826, 107827);

  script_name(english:"Flash Player <= 13.0.0.214 Multiple Vulnerabilities (APSB14-16)");
  script_summary(english:"Checks the version of Flash Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Flash Player installed on
the remote Windows host is equal or prior to 13.0.0.214. It is,
therefore, affected by the following vulnerabilities :

  - Multiple, unspecified errors exist that could allow
    cross-site scripting attacks. (CVE-2014-0531,
    CVE-2014-0532, CVE-2014-0533)

  - Multiple, unspecified errors exist that could allow
    unspecified security bypass attacks. (CVE-2014-0534,
    CVE-2014-0535)

  - An unspecified memory corruption issue exists that
    could allow arbitrary code execution. (CVE-2014-0536)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-16.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 14.0.0.125 or later.

Alternatively, Adobe has made version 13.0.0.223 available for those
installations that cannot be upgraded to 14.x.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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
foreach variant (make_list("Plugin", "ActiveX", "Chrome", "Chrome_Pepper"))
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
            # Chrome Flash <= 13.0.0.214
            variant == "Chrome_Pepper" &&
            (iver[0] == 13 && iver[1] == 0 && iver[2] == 0 && iver[3] <= 214)
          ) ||
          (variant != "Chrome_Pepper" &&
            (
             # < 13
             iver[0] < 13 ||
             # 13.0.0.x <= 13.0.0.214
             (
               iver[0] == 13 &&
               (
                 iver[1] == 0 &&
                 (
                   iver[2] == 0 &&
                   (
                     iver[3] <= 214
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
            info += '\n Product : Browser Plugin (for Firefox / Netscape / Opera)';
          }
          else if (variant == "ActiveX")
          {
            info += '\n Product : ActiveX control (for Internet Explorer)';
          }
          else if ("Chrome" >< variant)
          {
            info += '\n Product : Browser Plugin (for Google Chrome)';
          }
          info += '\n  Path              : ' + file +
                  '\n  Installed version : ' + ver;
          if (variant == "Chrome_Pepper")
            info += '\n  Fixed version     : 14.0.0.125 (Chrome PepperFlash)';
          else
          {
            fix = "14.0.0.125 / 13.0.0.223";
            info += '\n  Fixed version     : '+fix;
          }
          info += '\n';
        }
      }
    }
  }
}

if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0) security_hole(port:port, extra:info);
  else security_hole(port);
}
else
{
  if (thorough_tests)
    exit(0, 'No vulnerable versions of Adobe Flash Player were found.');
  else
    exit(1, 'Google Chrome\'s built-in Flash Player may not have been detected because the \'Perform thorough tests\' setting was not enabled.');
}
