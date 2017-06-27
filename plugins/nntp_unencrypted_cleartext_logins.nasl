#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57335);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_name(english:"NNTP Service Cleartext Login Permitted");
  script_summary(english:"Checks for cleartext authentication support.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NNTP server allows cleartext logins.");
  script_set_attribute(attribute:"description", value:
"The remote host is running an NNTP server that advertises that it
allows cleartext logins over unencrypted connections.  An attacker may
be able to uncover user names and passwords by sniffing traffic to the
server if a less secure authentication mechanism (i.e. LOGIN or
PLAIN) is used.");

  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc3977");
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc4643");

  script_set_attribute(attribute:"solution", value:
"Configure the service to support less secure authentication
mechanisms only over an encrypted channel.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/19");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("nntp_authentication.nasl");
  script_require_ports("Services/nntp");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"nntp", exit_on_fail:TRUE);

# Get a list of unencrypted methods.
methods = get_kb_list("nntp/" + port + "/auth");
if (isnull(methods))  exit(0, "The NNTP server listening on port " + port + " doesn't support unencrypted authentication.");

# Check if the LOGIN or PLAIN methods are supported.
auth_methods = make_list();
unencrypted_auth_methods = make_list();

foreach method (methods)
{
  auth_methods = make_list(auth_methods, method);
  if (method == "LOGIN" || method == "PLAIN")
  {
    unencrypted_auth_methods = make_list(unencrypted_auth_methods, method);
  }
}
if (max_index(unencrypted_auth_methods) == 0)
  exit(0, "The NNTP server listening on port " + port + " doesn't support unencrypted cleartext authentication.");

auth_methods = join(auth_methods, sep:", ");
unencrypted_auth_methods = join(unencrypted_auth_methods, sep:", ");

if (report_verbosity > 0)
{
  report =
    '\nThe NNTP server advertises the following SASL methods over an' +
    '\nunencrypted channel :' +
    '\n' +
    '\n  All supported methods : ' + auth_methods +
    '\n  Cleartext methods     : ' + unencrypted_auth_methods +
    '\n';
  security_note(port:port, extra:report);
}
else
{
  report = "The remote NNTP server allows cleartext logins.";
  security_note(port);
}

if (get_kb_item("Settings/PCI_DSS"))
  set_kb_item(name:"PCI/ClearTextCreds/" + port, value:report);
