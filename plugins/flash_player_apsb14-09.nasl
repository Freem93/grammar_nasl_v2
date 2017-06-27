#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73433);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id(
    "CVE-2014-0506",
    "CVE-2014-0507",
    "CVE-2014-0508",
    "CVE-2014-0509"
  );
  script_bugtraq_id(66208, 66699, 66701, 66703);
  script_osvdb_id(104598, 105535, 105536, 105537);

  script_name(english:"Flash Player <= 11.7.700.272 / 12.0.0.77 Multiple Vulnerabilities (APSB14-09)");
  script_summary(english:"Checks version of Flash Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Flash Player installed on
the remote Windows host is equal or prior to 11.7.700.272 / 11.8.x /
11.9.x / 12.0.0.77. It is, therefore, potentially affected multiple
vulnerabilities :

  - A use-after-free error exists that could lead to
    arbitrary code execution. (CVE-2014-0506)

  - A buffer overflow error exists that could lead to
    arbitrary code execution. (CVE-2014-0507)

  - An unspecified error exists that could allow a security
    bypass leading to information disclosure.
    (CVE-2014-0508)

  - An unspecified error exists that could allow cross-
    site scripting attacks. (CVE-2014-0509)");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/531839/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-09.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Flash Player version 11.7.700.275 / 13.0.0.182 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/09");

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
            # Chrome Flash <= 12.0.0.77
            variant == "Chrome_Pepper" &&
            (iver[0] == 12 && iver[1] == 0 && iver[2] == 0 && iver[3] <= 77)
          ) ||
          (variant != "Chrome_Pepper" &&
            (
             # < 11
             iver[0] < 11 ||
             # 11.x <= 11.7.700.272
             (
               iver[0] == 11 &&
               (
                 iver[1] < 7 ||
                 (
                   iver[1] == 7 &&
                   (
                     iver[2] < 700 ||
                     (iver[2] == 700 && iver[3] <= 272)
                   )
                 )
               )
             ) ||
             # 11.8.x
             (iver[0] == 11 && iver[1] == 8) ||
             # 11.9.x
             (iver[0] == 11 && iver[1] == 9) ||

             # 12.0.0.x <= 12.0.0.77
             (
               iver[0] == 12 &&
               (
                 iver[1] == 0 &&
                 (
                   iver[2] == 0 &&
                   (
                     iver[3] <= 77
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
            info += '\n  Fixed version     : 13.0.0.182 (Chrome PepperFlash)';
          else
          {
            if (ver =~ "^11\.7")
              fix = "11.7.700.275";
            else
              fix = "13.0.0.182";
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

  # XSS
  set_kb_item(name:'www/'+port+'/XSS', value: TRUE);

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
