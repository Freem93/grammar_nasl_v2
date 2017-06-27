#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70196);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/09/29 01:26:45 $");

  script_name(english:"Cisco Unity Connection Version");
  script_summary(english:"Gets the CUC version from SSH");

  script_set_attribute(attribute:"synopsis", value:"The remote host is a Cisco Unity Connection.");
  script_set_attribute(attribute:"description", value:"Cisco Unity Connection was found.");

  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps6509/index.html");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unity_connection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Cisco/CUC");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Cisco/CUC")) audit(AUDIT_OS_NOT, "Cisco Unity Connection");

version = get_kb_item("Host/Cisco/Unity_Connection/Version");
if (isnull(version)) exit(1, "Failed to get the Cisco Unity Connection version.");

if (report_verbosity > 0)
{
  report = '\n  Version : ' + version +
           '\n';
  security_note(port:0, extra:report);
}
else security_note(0);
