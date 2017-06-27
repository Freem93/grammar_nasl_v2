#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59196);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/11/11 21:06:45 $");

  script_name(english:"Adobe Flash Player Unsupported Version Detection");
  script_summary(english:"Checks if any Flash player versions are unsupported.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an unsupported version of Adobe Flash
Player.");
  script_set_attribute(attribute:"description", value:
"There is at least one unsupported version of Adobe Flash Player
installed on the remote Windows host.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/programs/policies/supported.html");
  # http://helpx.adobe.com/flash-player/kb/flash-player-9-support-discontinued.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9f12ecc3");
  # http://blogs.adobe.com/flashplayer/2013/05/extended-support-release-updated-to-flash-player-11-7.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1b34877");
  # http://blogs.adobe.com/flashplayer/2014/03/upcoming-changes-to-flash-players-extended-support-release.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01ced53b");
  # http://blogs.adobe.com/flashplayer/2015/05/upcoming-changes-to-flash-players-extended-support-release-2.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?706e2158");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a version of Adobe Flash Player that is currently
supported. Alternatively, remove the unsupported versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("flash_player_installed.nasl");
  script_require_keys("SMB/Flash_Player/installed");

  exit(0);
}

include("audit.inc");
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
        for (i=0; i<max_index(iver); i++)
          iver[i] = int(iver[i]);

        # 19.x is main stable / 18.x is extended release
        if (iver[0] < 18)
        {
          num = key - ("SMB/Flash_Player/"+variant+"/Version/");
          file = files["SMB/Flash_Player/"+variant+"/File/"+num];

          info = 'The following unsupported Flash player controls were detected :';
          if (variant == "Plugin")
          {
            info += '\n  Product : Browser Plugin (for Firefox / Netscape / Opera)';
          }
          else if (variant == "ActiveX")
          {
            info += '\n  Product : ActiveX control (for Internet Explorer)';
          }

          register_unsupported_product(product_name:'Adobe Flash Player',
                                       version:ver, cpe_base:"adobe:flash_player");

          info +=
            '\n  Path               : ' + file +
            '\n  Installed version  : ' + ver +
            '\n  Supported versions : 19.x / 18.x' +
            '\n';
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
else audit(AUDIT_NOT_INST, "An unsupported version of Adobe Flash Player");
