#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59837);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/07/03 19:14:35 $");

  script_name(english:"Check_MK Agent Detection");
  script_summary(english:"Detects a Check_MK Agent.");

  script_set_attribute(attribute:"synopsis", value:
"An information gathering service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a Check_MK Agent, which allows
clients to retrieve large amounts of data about the target.

Make sure the use of this program matches your corporate policy.");

  script_set_attribute(attribute:"see_also", value:"http://mathias-kettner.de/check_mk.html");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:mathias_kettner:check_mk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("find_service.nasl");
  script_require_keys("Services/check_mk");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item_or_exit("Services/check_mk");
banner = get_kb_item_or_exit("check_mk/banner/" + port);

# Extract the version from the response.
matches = eregmatch(string:banner, pattern:"Version: ([\w.]+)");
if (!isnull(matches))
  ver = matches[1];

# Store our findings.
set_kb_item(name:"Check_MK/Installed", value:port);
set_kb_item(name:"Check_MK/" + port + "/Banner", value:banner);

if (ver)
  set_kb_item(name:"Check_MK/" + port + "/Version", value:ver);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  if (ver)
  {
    report =
      '\n  Installed version : ' + ver +
      '\n';

    if (report_verbosity > 1)
    {
      bar = crap(data:"-", length:30);
      snip = bar + " snip " + bar;

      report +=
        '\nThe following information was provided by the remote service :' +
        '\n' +
        '\n  ' + snip;

      lines = split(banner, sep:'\n', keep:FALSE);
      for (i = 0; i < 20; i++)
      {
        report += '\n  ' + lines[i];
      }

      report +=
        '\n  ' + snip +
        '\n';
    }
  }
}

security_note(port:port, extra:report);
