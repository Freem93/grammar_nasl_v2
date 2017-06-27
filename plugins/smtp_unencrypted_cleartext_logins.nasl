#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54582);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/21 20:34:21 $");

  script_name(english:"SMTP Service Cleartext Login Permitted");
  script_summary(english:"Checks for cleartext authentication support.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote mail server allows cleartext logins."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running an SMTP server that advertises that it
allows cleartext logins over unencrypted connections.  An attacker may
be able to uncover user names and passwords by sniffing traffic to the
server if a less secure authentication mechanism (i.e.  LOGIN or
PLAIN) is used."
  );
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc4422");
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc4954");
  script_set_attribute(
    attribute:"solution", 
    value:
"Configure the service to support less secure authentication
mechanisms only over an encrypted channel."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smtp_authentication.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

# Get a list of unencrypted methods.
methods = get_kb_list("smtp/" + port + "/auth");
if (isnull(methods))
  exit(0, "The SMTP server on port " + port + " doesn't support unencrypted authentication.");

# Check if the LOGIN or PLAIN methods are supported.
auth_methods = '';
unencrypted_auth_methods = '';

foreach method (methods)
{
  auth_methods += ', ' + method;
  if (method == "LOGIN" || method == "PLAIN")
  {
    unencrypted_auth_methods += ', ' + method;
  }
}
if (!unencrypted_auth_methods)
  exit(0, "The SMTP server on port " + port + " doesn't support unencrypted cleartext authentication.");

auth_methods = substr(auth_methods, 2);
unencrypted_auth_methods = substr(unencrypted_auth_methods, 2);
if (report_verbosity > 0)
{
  report =
    '\nThe SMTP server advertises the following SASL methods over an' +
    '\nunencrypted channel :' +
    '\n' +
    '\n  All supported methods : ' + auth_methods +
    '\n  Cleartext methods     : ' + unencrypted_auth_methods +
    '\n';
  if ( get_kb_item("Settings/PCI_DSS") ) set_kb_item(name:"PCI/ClearTextCreds/" + port, value:report);
  security_note(port:port, extra:report);
}
else
{
  if ( get_kb_item("Settings/PCI_DSS") ) set_kb_item(name:"PCI/ClearTextCreds/" + port, 
							value:"The remote SMTP server allows cleartext logins.");
  security_note(port);
}
