#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59659);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/01/05 18:44:51 $");

  script_name(english:"Network UPS Tools Cleartext Authentication");
  script_summary(english:"Checks if the server supports encrypted authentication.");

  script_set_attribute(attribute:"synopsis", value:
"The UPS monitoring tool on the remote host does not support encrypted
authentication.");
  script_set_attribute(attribute:"description", value:
"The remote Network UPS Tools does not support exchanging credentials
through an encrypted channel. An unauthenticated, remote attacker can
exploit this to perform a man-in-the-middle attack, intercept
credentials, and alter the settings on the UPS that the server
manages.");
  # http://www.networkupstools.org/docs/developer-guide.chunked/ar01s09.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb057f01");
  script_set_attribute(attribute:"see_also", value:"http://www.networkupstools.org/docs/user-manual.chunked/ar01s09.html");
  script_set_attribute(attribute:"solution", value:
"Enable StartTLS support on the server using the 'CERTFILE' directive.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:networkupstools:nut");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("nut_starttls.nasl");
  script_require_ports("Services/nut", 3493);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Get the ports that NUT have been found on.
port = get_service(svc:"nut", exit_on_fail:TRUE);

# Check how the port is secured.
if (get_kb_item("nut/" + port + "/starttls"))
  exit(0, "The Network UPS Tools server running on port " + port + " supports StartTLS.");

report = "The Network UPS Tools server on port " + port + " does not support encrypted logins.";
set_kb_item(name:"PCI/ClearTextCreds/" + port, value:report);

security_warning(port);
