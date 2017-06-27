#
# (C) Tenable Network Security, Inc.

include( 'compat.inc' );

if (description)
{
 script_id(11753);
 script_version ("$Revision: 1.18 $");
 script_bugtraq_id(7952);
 script_osvdb_id(53325, 53326);

 script_name(english:"SquirrelMail Multiple Remote Vulnerabilities");
 script_summary(english:"Determine if squirrelmail reads arbitrary files");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running SquirrelMail, a web-based mail server.

There is a flaw in the remote installation that could allow an
attacker with a valid webmail account to read, move and delete arbitrary
files on this server, with the privileges of the HTTP server.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to SquirrelMail 1.2.12 when it is available.'
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2003/Jun/191'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/18");
 script_cvs_date("$Date: 2016/12/14 20:33:27 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

dir = make_list( cgi_dirs(), "/mail");


foreach d (dir)
{
 w = http_send_recv3(method:"GET", item:d + "/src/redirect.php", port:port);
 if (isnull(w)) exit(1, "The web server did not answer");
 res = strcat(w[0], w[1], '\r\n', w[2]);

 if(egrep(pattern:"SquirrelMail version (0\..*|1\.([0-1]\..*|2\.([0-9]|1[01])))[^0-9]", string:res))
 {
  security_hole(port);
  exit(0);
 }
}
