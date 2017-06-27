#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(26925);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2013/01/25 01:19:11 $");

 script_name(english:"VNC Server Unauthenticated Access");
 script_summary(english:"Tries to authenticate using a type of None");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote VNC server does not require authentication." );
 script_set_attribute(attribute:"description", value:
"The VNC server installed on the remote host allows an attacker
to connect to the remote host as no authentication is required
to access this service.

** The VNC server sometimes sends the connected user to the XDM login
** screen. Unfortunately, Nessus cannot identify this situation.
** In such a case, it is not possible to go further without valid
** credentials and this alert may be ignored." );
 script_set_attribute(attribute:"solution", value:
"Disable the No Authentication security type." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/05");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
 script_dependencies("vnc_security_types.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/vnc", 5900);

 exit(0);
}

include("global_settings.inc");

if (report_paranoia < 1)
{
  os = get_kb_item("Host/OS");
  if ("SuSE" >< os) exit(1, "This script is prone to FPs against SuSE systems.");
}

port = get_kb_item("VNC/SecurityNoAuthentication");
if (!isnull(port))
  security_hole(port);

