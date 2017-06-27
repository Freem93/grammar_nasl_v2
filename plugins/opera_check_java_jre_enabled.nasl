#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65742);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/05/06 17:31:06 $");

  script_name(english:"Oracle Java JRE Enabled (Opera)");
  script_summary(english:"Checks kb item");

  script_set_attribute(attribute:"synopsis", value:"The remote host has Java JRE enabled for Opera.");
  script_set_attribute(attribute:"description", value:"Oracle Java JRE is enabled in Opera.");
  script_set_attribute(attribute:"solution", value:"Disable Java unless it is needed.");
  script_set_attribute(attribute:"see_also", value:"http://www.java.com/en/download/help/disable_browser.xml");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("oracle_java_jre_enabled.nasl");
  script_require_keys("SMB/Java/JRE/opera_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Get a list of users that Java is still enabled in
if (!get_kb_item("SMB/Java/JRE/universally_enabled")) exit(0, "Java has been universally disabled.");

users = get_kb_item_or_exit("SMB/Java/JRE/opera_enabled");
users = str_replace(string:users, find:',', replace:'\n  ');

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\nJava is enabled in Opera for the following users :' +
    '\n' +
    '  ' + users + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
