#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22876);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-5428");
  script_bugtraq_id(20598);
  script_osvdb_id(29790);

  script_name(english:"Cerberus Helpdesk rpc.php Arbitrary Ticket Information Disclosure");
  script_summary(english:"Gets requestors for a Cerberus ticket");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by an
information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cerberus Helpdesk, a web-based helpdesk
suite written in PHP. 

The installed version of Cerberus Helpdesk on the remote host allows
an unauthenticated attacker to retrieve information about ticket
requesters through the 'rpc.php' script." );
 script_set_attribute(attribute:"solution", value:
"Patch the affected file or update to the latest version of Cerberus
Helpdesk." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/10/15");
 script_cvs_date("$Date: 2013/05/22 01:13:34 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/cerberus", "/cerberus-gui", "/helpdesk", "/tickets", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  ticket = 1;
  r = http_send_recv3(method:"GET", port: port,
    item:string( dir, "/rpc.php?",
      "cmd=display_get_requesters&",
      "id=", ticket ));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we get a response (eg, see a link to add a requester).
  #
  # nb: this works even if the ticket number is invalid.
  if ('input type="text" name="requester_add"' >< res)
  {
    security_warning(port);
    exit(0);
  }
}
