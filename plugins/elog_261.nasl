#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20750);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-0347", "CVE-2006-0348");
  script_bugtraq_id(16315);
  script_osvdb_id(22646, 22647);
 
  script_name(english:"ELOG < 2.6.1 Multiple Remote Vulnerabilities (Traversal, FS)");
  script_summary(english:"Checks for multiple vulnerabilities in ELOG < 2.6.1");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be using ELOG, a web-based electronic
logbook application. 

The version of ELOG installed on the remote host fails to filter
directory traversal strings before processing GET requests.  An
attacker can exploit this issue to retrieve the contents of arbitrary
files from the remote host, subject to the privileges under which ELOG
runs. 

In addition, the application is reportedly affected by a format string
vulnerability in the 'write_logfile'.  Provided logging is enabled, an
attacker may be able to exploit this via the 'uname' parameter of the
login form to crash the application or execute arbitrary code
remotely." );
 script_set_attribute(attribute:"see_also", value:"http://midas.psi.ch/elogs/Forum/1608" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ELOG version 2.6.1 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/10/25");
 script_cvs_date("$Date: 2016/09/08 13:32:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);


# If the server looks like ELOG...
banner = get_http_banner(port:port);
if (banner && "Server: ELOG HTTP" >< banner) {
  # Try to exploit the flaw to read /etc/passwd.
  r = http_send_recv3(method:"GET",item:"/../../../../../../../../../../etc/passwd", port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  if (egrep(pattern:"root:.*:0:[01]:", string:res)) {
    security_warning(port:port, extra: res);
    exit(0);
  }
}
