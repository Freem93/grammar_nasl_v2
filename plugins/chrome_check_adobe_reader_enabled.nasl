#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66518);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/05/20 20:57:40 $");

  script_name(english:"Adobe Reader Enabled in Browser (Google Chrome)");
  script_summary(english:"Checks kb item");

  script_set_attribute(attribute:"synopsis", value:"The remote host has Adobe Reader enabled for Google Chrome.");
  script_set_attribute(attribute:"description", value:"Adobe Reader is enabled in Google Chrome.");
  script_set_attribute(attribute:"solution", value:"Disable Adobe Reader unless it is needed.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_enabled_in_browser.nasl");
  script_require_keys("SMB/Acroread/chrome_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Get a list of users that Adobe is still enabled for
users = get_kb_item_or_exit("SMB/Acroread/chrome_enabled");
users = str_replace(string:users, find:',', replace:'\n ');

port = get_kb_item('SMB/transport');
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\nAdobe Reader is enabled in Google Chrome for the following users :' +
    '\n' +
    '  ' + users + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
