#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57334);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2011/12/19 19:03:57 $");

  script_name(english:"Anonymous NNTP Authentication Enabled");
  script_summary(english:"Checks for anonymous authentication support.");

  script_set_attribute(attribute:"synopsis", value:
"Anonymous authentication is allowed on the remote NNTP server.");
  script_set_attribute(attribute:"description", value:
"This NNTP service allows anonymous authentication.  Any remote user
may connect and authenticate without providing a password or unique
credentials.");

  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc4422");
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc4505");
  script_set_attribute(attribute:"see_also", value:"http://tools.ietf.org/html/rfc4643");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/19");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencies("nntp_authentication.nasl");
  script_require_ports("Services/nntp");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"nntp", exit_on_fail:TRUE);

# Get a list of both encrypted and unencrypted methods.
methods = make_list();

list = get_kb_list("nntp/" + port + "/auth");
if (!isnull(list))  methods = make_list(methods, list);

list = get_kb_list("nntp/" + port + "/auth_tls");
if (!isnull(list))  methods = make_list(methods, list);

if (max_index(methods) == 0)
  exit(0, "The NNTP server listening on port " + port + " doesn't support authentication.");

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

# Store whether this port supports ANONYMOUS authentication in the KB.
set_kb_item(name:"nntp/" + port + "/anonymous", value:anonymous);

if (!anonymous)
  exit(0, "The NNTP server listening on port " + port + " doesn't support ANONYMOUS authentication.");

security_note(port);
