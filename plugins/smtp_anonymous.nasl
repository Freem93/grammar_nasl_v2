#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54581);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2011/05/19 15:24:25 $");

  script_name(english:"Anonymous SMTP Authentication Enabled");
  script_summary(english:"Checks for anonymous authentication support.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"Anonymous authentication is allowed on the remote SMTP server."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This SMTP service allows anonymous authentication.  Any remote user
may connect and authenticate without providing a password or unique
credentials.  This may effectively turn the remote server into an open
mail relay."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tools.ietf.org/html/rfc2245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tools.ietf.org/html/rfc4422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tools.ietf.org/html/rfc4505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tools.ietf.org/html/rfc4954"
  );

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencies("smtp_authentication.nasl");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);

# Get a list of both encrypted and unencrypted methods.
methods = make_list();
list = get_kb_list("smtp/" + port + "/auth");
if (!isnull(list))
  methods = make_list(methods, list);
list = get_kb_list("smtp/" + port + "/auth_tls");
if (!isnull(list))
  methods = make_list(methods, list);
if (!max_index(methods))
  exit(0, "SMTP server on port " + port + " doesn't support authentication.");

# Check if the ANONYMOUS method is supported.
anonymous = FALSE;
foreach method (methods)
{
  if (method == "ANONYMOUS")
  {
    anonymous = TRUE;
    break;
  }
}
if (!anonymous)
  exit(0, "SMTP server on port " + port + " doesn't support ANONYMOUS authentication.");

security_note(port);
