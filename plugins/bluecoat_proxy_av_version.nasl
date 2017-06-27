#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69929);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/09/18 00:31:18 $");

  script_name(english:"Blue Coat ProxyAV Detection");
  script_summary(english:"Looks at ICAP and HTTP headers.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is a Blue Coat ProxyAV appliance.");
  script_set_attribute(attribute:"description", value:"Blue Coat ProxyAV, an anti-malware appliance, was found.");

  script_set_attribute(attribute:"see_also", value:"https://www.bluecoat.com/products/proxyav");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:bluecoat:proxyav");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "icap_version.nasl");
  script_require_ports("Services/icap", "Services/www", 80, 443, 1344, 8081, 8082);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

global_var found, rel, ver;

function ver_http()
{
  local_var matches, port, ports, res;

  # Test every HTTP port, the interface can listen on multiple ports.
  ports = get_kb_list("Services/www");
  if (isnull(ports))
    return NULL;

  # Squash any deformities.
  ports = make_list(ports);
  if (max_index(ports) == 0)
    return NULL;

  foreach port (ports)
  {
    res = http_send_recv3(
      method : "GET",
      item   : "/self_upgrade.html",
      port   : port
    );

    if (isnull(res))
      continue;

    # Check if the page is demanding credentials, but still looks
    # right.
    if ('WWW-Authenticate: Basic realm="ProxyAV"' >< res[1])
    {
      found = TRUE;
      continue;
    }

    # Check if the page indicates that this is ProxyAV.
    if ("Proxy-agent: BlueCoat-ProxyAV" >< res[1])
    {
      found = TRUE;

      # Check if this page has the version information we want.
      if ('name="CurrentVersion"' >< res[2])
      {
        matches = eregmatch(string:res[2], pattern:'<input[^>]*name="CurrentVersion" +value="([0-9.]+)" *>');
        if (isnull(matches))
          continue;
        ver = matches[1];

        matches = eregmatch(string:res[2], pattern:"Software Release id: (\d+)");
        if (isnull(matches))
          continue;
        rel = matches[1];

        # Store web server information.
        set_kb_item(name:"www/bluecoat_proxyav", value:port);
        set_kb_item(name:"www/bluecoat_proxyav/" + port + "/version", value:ver);
        set_kb_item(name:"www/bluecoat_proxyav/" + port + "/release_id", value:rel);

        break;
      }
    }
  }
}

function ver_icap()
{
  local_var port, ports;

  # We shouldn't find more than one ICAP instance, but be safe.
  ports = get_kb_list("icap/bluecoat_proxyav");
  if (isnull(ports))
    return NULL;

  # Arbitrarily pick the first instance.
  ports = make_list(ports);
  if (max_index(ports) == 0)
    return NULL;
  port = ports[0];

  found = TRUE;
  ver = get_kb_item("icap/bluecoat_proxyav/" + port + "/version");
  rel = get_kb_item("icap/bluecoat_proxyav/" + port + "/release_id");
}

found = FALSE;

# First, try to get the info with HTTP. ICAP version info is gotten
# elsewhere, but HTTP info is only gathered here. The HTTP interface
# is locked down by default, so this is likely to fail.
ret = ver_http();

# If we couldn't find a matching HTTP service, try the more reliable
# ICAP service, which is provides the version number by default. The
# ICAP script is generic, so it could be on any port. Note, however,
# that this is an appliance, meaning that finding a ProxyAV service on
# any port is good enough.
if (isnull(ver)) ver_icap();

if (!found) audit(AUDIT_HOST_NOT, "Blue Coat ProxyAV");

# Save our findings.
kb = "Host/BlueCoat/ProxyAV";
set_kb_item(name:kb, value:TRUE);
if (!isnull(ver))
{
  set_kb_item(name:kb + "/Version", value:ver);
  set_kb_item(name:kb + "/Release_ID", value:rel);
}

# Report our findings.
report = NULL;
if (!isnull(ver) && report_verbosity > 0)
{
  report =
    '\nThe remote host is a Blue Coat ProxyAV appliance :' +
    '\n' +
    '\n  Firmware version    : ' + ver +
    '\n  Firmware release ID : ' + rel +
    '\n';
}

security_note(port:0, extra:report);
