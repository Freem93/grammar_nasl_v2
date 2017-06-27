#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56259);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 16:01:14 $");

  script_cve_id(
    "CVE-2011-2426",
    "CVE-2011-2427",
    "CVE-2011-2428",
    "CVE-2011-2429",
    "CVE-2011-2430",
    "CVE-2011-2444"
  );
  script_bugtraq_id(
    49710,
    49714,
    49715,
    49716,
    49717,
    49718
  );
  script_osvdb_id(75625, 75626, 75627, 75628, 75629, 75630);

  script_name(english:"Flash Player <= 10.3.183.7 Multiple Vulnerabilities (APSB11-26)");
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
the remote Windows host is 10.3.183.7 or earlier.  It is, therefore,
reportedly affected by several critical vulnerabilities :

  - Multiple AVM stack overflow vulnerabilities could lead
    to code execution. (CVE-2011-2426, CVE-2011-2427)

  - A logic error issue could lead to code execution or 
    a browser crash. (CVE-2011-2428)

  - A Flash Player security control bypass vulnerability 
    could lead to information disclosure. (CVE-2011-2429)

  - A streaming media logic error vulnerability could lead
    to code execution. (CVE-2011-2430)

  - A universal cross-site scripting vulnerability could be
    abused to take actions on a user's behalf on any 
    website if the user is tricked into visiting a 
    malicious website. Note that this issue is reportedly
    being actively exploited in targeted attacks. 
    (CVE-2011-2444)"
  );

  # https://github.com/zrong/blog/tree/master/flashplayer_crash_on_netstream_play/project
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ace6f27f");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-26.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Flash version 10.3.183.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/22");

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

# nb: we're checking for versions less than *or equal to* the cutoff!
#     Cutoff here is 10.3.183.7 ; the next release was 10.3.183.10.
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
                  iver[2] < 183 ||
                  (iver[2] == 183 && iver[3] <= 7)
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
                  '\n  Fixed version     : 10.3.183.10';
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
