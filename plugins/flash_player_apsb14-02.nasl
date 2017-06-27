#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71951);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2014-0491", "CVE-2014-0492");
  script_bugtraq_id(64807, 64810);
  script_osvdb_id(101982, 101983);

  script_name(english:"Flash Player <= 11.7.700.257 / 11.9.900.170 Multiple Vulnerabilities (APSB14-02)");
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
"According to its version, the instance of Flash Player installed on the
remote Windows host is equal or prior to 11.7.700.257 / 11.8.x or
11.9.900.170.  It is, therefore, potentially affected by the following
vulnerabilities :

  - An unspecified vulnerability exists that can be used to
    bypass Flash Player security protections.
    (CVE-2014-0491)

  - An unspecified vulnerability exists that can be used to
    bypass memory address layout randomization.
    (CVE-2014-0492)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-014/");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-02.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Adobe Flash Player version 11.7.700.260 / 12.0.0.38 or
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/14");

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
            # Chrome Flash <= 11.9.900.170
            variant == "Chrome_Pepper" &&
            (
               iver[0] == 11 &&
               (
                 iver[1] == 9 &&
                 (
                   iver[2] < 900 ||
                   (iver[2] == 900 && iver[3] <= 170)
                 )
               )
            )
          ) ||
          (variant != "Chrome_Pepper" &&
            (
             # < 11
             iver[0] < 11 ||
             # 11.x <= 11.7.700.257
             (
               iver[0] == 11 &&
               (
                 iver[1] < 7 ||
                 (
                   iver[1] == 7 &&
                   (
                     iver[2] < 700 ||
                     (iver[2] == 700 && iver[3] <= 257)
                   )
                 )
               )
             ) ||
             # 11.8.x
             (iver[0] == 11 && iver[1] == 8) ||
             # 11.9.x <= 11.9.900.170
             (
               iver[0] == 11 &&
               (
                 iver[1] == 9 &&
                 (
                   iver[2] < 900 ||
                   (iver[2] == 900 && iver[3] <= 170)
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
            info += '\n  Fixed version     : 12.0.0.41 (Chrome PepperFlash)';
 	  else
          {
            if (ver =~ "^11\.7")
              fix = "11.7.700.260";
            else
              fix = "12.0.0.38";
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
