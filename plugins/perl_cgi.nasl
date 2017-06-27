#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10173);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2016/08/29 13:57:36 $");
 script_cve_id("CVE-1999-0509");
 script_osvdb_id(200);

 script_name(english:"Web Server /cgi-bin Perl Interpreter Access");
 script_summary(english:"checks for the presence of /cgi-bin/perl");

 script_set_attribute(attribute:"synopsis", value:"It is possible to execute arbitrary commands on the remote system.");
 script_set_attribute(attribute:"description", value:
"The 'Perl' CGI is installed and can be launched as a CGI.
This is equivalent to giving a free shell to an attacker,
with the http server privileges (usually root or nobody)." );
 script_set_attribute(attribute:"solution", value:"Remove it from /cgi-bin");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"1995/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

no404 = get_kb_item(strcat("www/no404/", port));
l = list_uniq(make_list("/", cgi_dirs()));

url_l = make_list();

foreach d (l)
{
 foreach prog (make_list("perl", "perl.exe"))
 {
   u = strcat(d, "/", prog, "?-v");
   w = http_send_recv3(port: port, item: u, method:"GET", exit_on_fail: 1);
   s = w[2];
   if (strlen(s) < 2048 && '\0' >!< s &&	# Exclude binary exec
       "This is perl " >< s && "Larry Wall" >< s && "Artistic License" >< s)
   {
     e = get_vuln_report(items: u, port: port);
     security_hole(port: port, extra: e);
     exit(0);
   }
 }
}

if (max_index(url_l) > 0)
{
  e = get_vuln_report(items: url_l, port: port);
  security_hole(port: port, extra: e);
  exit(0);
}

exit(0, "No vulnerable CGI was found on port "+port+".");
