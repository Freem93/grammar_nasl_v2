#
# (C) Tenable Network Security, Inc.
#

# Affected: MondoSearch 4.4.5147 and below.
#           MondoSearch 4.4.5156 and above are NOT vulnerable.
#
# References:
#
# Message-ID: <20021010180935.14148.qmail@mail.securityfocus.com>
# From:"thefastkid" <thefastkid@ziplip.com>
# To:bugtraq@securityfocus.com
# Subject: MondoSearch show the source of all files
#


include("compat.inc");

if(description)
{
 script_id(11163);
 script_version ("$Revision: 1.23 $");
 script_cvs_date("$Date: 2013/01/25 01:19:09 $");

 script_cve_id("CVE-2002-1528");
 script_osvdb_id(11871);
  
 script_name(english:"MondoSearch MsmMask.exe Arbitrary Script Source Disclosure");
 script_summary(english:"Checks for the presence of /cgi-bin/msmMask.exe");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The msmmask.exe CGI is installed. Some versions allow an attacker to
read the source of any file in your web server's directories by using 
the 'mask' parameter." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your MondoSearch to version 4.4.5156 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/11/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/10/10");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2013 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "httpver.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/ASP");
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (! can_host_asp(port:port) ) exit(0);


foreach dir (cgi_dirs())
{
  p = string(dir, "/MsmMask.exe");
  q = string(p, "?mask=/nessus", rand(), ".asp");

  res = http_send_recv3(method:"GET", item:q, port:port);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  if (egrep(pattern: "Failed to read the maskfile .*nessus.*\.asp",string:res[2], icase: 1))
  {
    security_warning(port);
    exit(0);
  }

# Version at or below 4.4.5147
  if (egrep(pattern: "MondoSearch for Web Sites (([0-3]\.)|(4\.[0-3]\.)|(4\.4\.[0-4])|(4\.4\.50)|(4\.4\.51[0-3])|(4\.4\.514[0-7]))", string:res[2]))
  {
    security_warning(port);
    exit(0);
  }
}
