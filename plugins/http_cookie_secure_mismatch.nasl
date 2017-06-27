#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69826);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_name(english:"HTTP Cookie 'secure' Property Transport Mismatch");
  script_summary(english:"Examines the 'secure' property of each cookie.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server sent out a cookie with a secure property that
does not match the transport on which it was sent.");
  script_set_attribute(attribute:"description", value:
"The remote web server sends out cookies to clients with a 'secure'
property that does not match the transport, HTTP or HTTPS, over which
they were received.  This may occur in two forms :

  1. The cookie is sent over HTTP, but has the 'secure'
     property set, indicating that it should only be sent
     over a secure, encrypted transport such as HTTPS.
     This should not happen.

  2. The cookie is sent over HTTPS, but has no 'secure'
     property set, indicating that it may be sent over both
     HTTP and HTTPS transports. This is common, but care
     should be taken to ensure that the 'secure' property
     not being set is deliberate.");

  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/rfc6265");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("http_cookie_jar.inc");
include("global_settings.inc");
include("misc_func.inc");

function boolean()
{
  if (_FCT_ANON_ARGS[0])
    return "true";

  return "false";
}

# Get the full list of ports that have cookies.
items = get_kb_list_or_exit("Cookies/webmirror-*/value/*");
items = keys(items);

# Remove the part of the key name we don't care about, yet.
ports = make_list();
foreach port (items)
{
  port = ereg_replace(string:port, pattern:"^Cookies/webmirror-(\d+)/.*$", replace:"\1");
  ports = make_list(ports, port);
}
ports = list_uniq(ports);

if (max_index(ports) == 0)
  audit(AUDIT_HOST_NONE, "HTTP cookies.");

# Branch so each instance of the script handles a port.
port = branch(ports);

# Get the cookies sent on this port.
load_cookiejar(jar:"webmirror-" + port);
names = get_http_cookie_keys(port:port, name_re:".*");
if (max_index(names) == 0)
  exit(0, "No HTTP cookies were received on port " + port + ".");

# Determine whether this port is HTTP or HTTPS.
encaps = get_kb_item("Transports/TCP/" + port);
ssl = (!isnull(encaps) && encaps > ENCAPS_IP);

# Check that the 'secure' attribute's existence corresponds with the
# use of SSL.
exceptions = make_list();
foreach name (sort(names))
{
  cookie = get_http_cookie_from_key(name);
  if (cookie["secure"] == ssl)
    continue;

  info =
    '\n  Domain   : ' + cookie["domain"] +
    '\n  Path     : ' + cookie["path"] +
    '\n  Name     : ' + cookie["name"] +
    '\n  Value    : ' + cookie["value"] +
    '\n  Secure   : ' + boolean(cookie["secure"]) +
    '\n  HttpOnly : ' + boolean(cookie["httponly"]);

  exceptions = make_list(exceptions, info);
}

if (max_index(exceptions) == 0)
  exit(0, "No HTTP cookies with mismatched 'secure' properties were found on port " + port + ".");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  if (ssl)
  {
    if (max_index(exceptions) > 1)
      s = "s do";
    else
      s = " does";

    report = '\nThe following cookie' + s + ' not have the \'secure\' property enabled, despite being served over HTTPS :';
  }
  else
  {
    if (max_index(exceptions) > 1)
      s = "s have";
    else
      s = " has";

    report = '\nThe following cookie' + s + ' the \'secure\' property enabled, despite being served over HTTP :';
  }

  report +=
    '\n  ' + join(exceptions, sep:'\n') +
    '\n';
}

security_note(port:port, extra:report);
