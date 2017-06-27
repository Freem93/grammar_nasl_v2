#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66445);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 16:01:15 $");

  script_cve_id(
    "CVE-2013-2728",
    "CVE-2013-3324",
    "CVE-2013-3325",
    "CVE-2013-3326",
    "CVE-2013-3327",
    "CVE-2013-3328",
    "CVE-2013-3329",
    "CVE-2013-3330",
    "CVE-2013-3331",
    "CVE-2013-3332",
    "CVE-2013-3333",
    "CVE-2013-3334",
    "CVE-2013-3335"
  );
  script_bugtraq_id(
    59889,
    59890,
    59891,
    59892,
    59893,
    59894,
    59895,
    59896,
    59897,
    59898,
    59899,
    59900,
    59901
  );
  script_osvdb_id(
    93322,
    93323,
    93324,
    93325,
    93326,
    93327,
    93328,
    93329,
    93330,
    93331,
    93332,
    93333,
    93334
  );

  script_name(english:"Flash Player <= 10.3.183.75 / 11.7.700.169 Multiple Vulnerabilities (APSB13-14)");
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
remote Windows host is 11.x equal or prior to 11.7.700.169, or 10.x
equal or prior to 10.3.183.75.  It is, therefore, potentially affected
by several memory corruption errors that could lead to code
execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-14.html");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Adobe Flash Player version 10.3.183.86 / 11.7.700.202 or
later, or Google Chrome PepperFlash 11.7.700.202 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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
            (variant != "Chrome_Pepper" &&
             (
             # 10.x <= 10.3.183.86
               (
                 iver[0] == 10 &&
                 (
                   iver[1] < 3 ||
                   (
                     iver[1] == 3 &&
                     (
                       iver[2] < 183 ||
                       (iver[2] == 183 && iver[3] <= 75)
                     )
                   )
                 )
               )
             )
           ) ||
             # 11.x <= 11.7.700.169
            (
              iver[0] == 11 &&
              (
                iver[1] < 7 ||
                (
                  iver[1] == 7 &&
                  (
                    iver[2] < 700 ||
                    (iver[2] == 700 && iver[3] <= 169)
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
            info += '\n  Fixed version     : 11.7.700.202 (Chrome PepperFlash)';
          else
            info += '\n  Fixed version     : 10.3.183.86 / 11.7.700.202';
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