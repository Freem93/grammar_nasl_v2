#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10025);
 script_bugtraq_id(142);
 script_osvdb_id(21);
 script_version ("$Revision: 1.43 $");
 script_cve_id("CVE-1999-1462");
 
 script_name(english:"Big Brother bb-hist.sh History Module Directory Traversal");
 script_summary(english:"Read arbitrary files using the CGI bb-hist.sh.");

 script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by a
directory traversal vulnerability." );
 script_set_attribute( attribute:"description", value:
"The version of Big Brother running on the remote is affected by a
directory traversal vulnerability in the 'HISTFILE' parameter of the
'bb-hist.sh' CGI. A remote attacker can exploit this to read sensitive
information from the system." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/1999/Apr/251"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Big Brother 1.09d or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/04/26");
 
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
  
 script_copyright("This script is Copyright (C) 1999-2016 Tenable Network Security, Inc."); 

 script_dependencie("http_version.nasl", "web_traversal.nasl");
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
if (get_kb_item("www/"+port+"/generic_traversal"))
  exit(0, 'The web server on port '+port+' is vulnerable to directory traversal.');


foreach dir (cgi_dirs())
{
url = string(dir, "/bb-hist.sh?HISTFILE=../../../../../etc/passwd");
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: TRUE);

if(egrep(pattern:"root:.*:0:[01]:.*", string:res[2]))
   {
    e = '\nThe follwing URL exhibits the flaw :\n' 
      + build_url(port:port, qs: url) + '\n';
    if (report_verbosity > 1)
      e += 'It produces the following output :\n' + res[2] + '\n';
    security_warning(port:port, extra: e);
    exit(0);
   }
}
