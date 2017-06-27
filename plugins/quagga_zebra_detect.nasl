#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59796);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/05 21:03:16 $");

  script_name(english:"Quagga Zebra Detection");
  script_summary(english:"Looks at login page");

  script_set_attribute(attribute:"synopsis", value:
"A console for routing software is running on the remote host.");

  script_set_attribute(attribute:"description", value:
"Zebra, the core daemon of the Quagga routing software suite, is
running on the remote host.");

  script_set_attribute(attribute:"see_also", value:"http://www.nongnu.org/quagga/");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:quagga:quagga");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/zebra", 2601);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Quagga Zebra";

# Get information from service detection.
port = get_service(svc:"zebra", default:2601, exit_on_fail:TRUE);
login = get_kb_item_or_exit("zebra/banner/" + port);

# Check if this is actually Quagga as opposed to GNU Zebra.
if (login !~ "[Qq]uagga")
  audit(AUDIT_NOT_DETECT, app, port);

# Trim the banner down from an entire login screen to the single line
# we're interested in.
banner = NULL;
regex = "^Hello, this is [Qq]uagga \(version (([.\d]+).*)\)\.";
lines = egrep(string:login, pattern:regex);
if (lines)
{
  foreach line (split(lines, sep:'\r\n', keep:FALSE))
  {
    if (line =~ regex)
    {
      banner = chomp(line);
      break;
    }
  }
}

if (isnull(banner))
  exit(1, "Failed to parse banner for " + app + " from login page presented on port " + port + ".");

# Parse the version number out of the banner.
matches = eregmatch(string:banner, pattern:regex);
if (isnull(matches))
  audit(AUDIT_SERVICE_VER_FAIL, app, port);
ver = matches[2];
fullver = matches[1];

# Store our findings in the KB.
kb = "Quagga/";
set_kb_item(name:kb + "Installed", value:port);

kb += port + "/";
set_kb_item(name:kb + "Banner", value:banner);
set_kb_item(name:kb + "Version", value:ver);
set_kb_item(name:kb + "FullVersion", value:fullver);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + fullver +
    '\n';
}

security_note(port:port, extra:report);
