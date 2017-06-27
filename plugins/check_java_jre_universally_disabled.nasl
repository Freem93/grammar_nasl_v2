#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65739);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/05/06 17:31:06 $");

  script_name(english:"Oracle Java JRE Universally Enabled");
  script_summary(english:"Checks if Java is disabled through the Control Panel");

  script_set_attribute(attribute:"synopsis", value:
"Oracle Java JRE has not been universally disabled on the remote
host.");
  script_set_attribute(attribute:"description", value:
"Oracle Java JRE has not been universally disabled on the remote host
via the Java control panel.  Note that while Java can be individually
disabled for each browser, universally disabling Java prevents it from
running for all users and browsers.");
  script_set_attribute(attribute:"solution", value:"Disable Java universally unless it is needed.");
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
  script_require_keys("SMB/Java/JRE/universally_enabled");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

if (get_kb_item("SMB/Java/JRE/universally_enabled"))
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  security_note(port);
  exit(0);
}
exit(0, "Java has been universally disabled.");
