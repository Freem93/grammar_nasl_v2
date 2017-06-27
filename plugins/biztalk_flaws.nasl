#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(11638);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2012/05/31 21:25:30 $");

 script_cve_id("CVE-2003-0117", "CVE-2003-0118");
 script_bugtraq_id(7469, 7470);
 script_osvdb_id(10103, 10104, 13406);
 script_xref(name:"MSFT", value: "MS03-016");
 script_xref(name:"Secunia", value:"8707");

 script_name(english:"Microsoft BizTalk Server Multiple Remote Vulnerabilities");
 script_summary(english:"Determines if BizTalk is installed");

 script_set_attribute(attribute:"synopsis", value:
"The remote business process management service has multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running Microsoft BizTalk server. 

There are two flaws in this software that could allow an attacker to
issue a SQL insertion attack or to execute arbitrary code on the
remote host. 

Note that Nessus solely relied on the presence of a Biztalk DLL to
issue this alert so it might be a false positive.");
 script_set_attribute(
   attribute:"see_also",
   value:"http://technet.microsoft.com/en-us/security/bulletin/ms03-016"
 );
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patches referenced in Microsoft Security Bulletin
MS03-016.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/04/30");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/20");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (get_kb_item("www/no404/"+port)) exit(1, "The web server on port "+port+" does not return 404 codes.");

if (thorough_tests)
  dirs = get_kb_list(string("www/", port, "/content/directories"));
if(isnull(dirs))dirs = make_list();
dirs = list_uniq(make_list(dirs, cgi_dirs()));
	
foreach d (dirs)
{
   url = d + "/biztalkhttpreceive.dll";
   if (! is_cgi_installed3(item:url, port:port) ) 
     continue;
 
   rq = http_mk_post_req( port: port, data: rand_str(length: 8),
       			  item: url);
 
 #
 # We might do multiple retries as the CGI sometimes stalls
 # when it has received a bad request first.
 # 
  for (i = 0; i < 3; i ++)
  {
    r = http_send_recv_req(port: port, req: rq, exit_on_fail: 1);
    if ("HTTP/1.1 500 Internal Server Error" >< r[0])
    {
      if (report_verbosity > 0)
      {
        report = '\n  URL : ' + build_url(port:port, qs:url) +
                 '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }

    # The script did not stall
    if ("HTTP/1.1 100 Continue" >!< r[0] ) break;
    sleep(1);
 }
}
