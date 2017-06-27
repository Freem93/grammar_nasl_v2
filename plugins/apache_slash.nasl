#
# This script was written by John Lampe (j_lampe@bellsouth.net)
#

#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - script description, more verbose report, check for k < 16 in find_index(), script id [RD]
# - revised title, changed family (9/4/09)

include("compat.inc");

if(description)
{
  script_id(10440);
  script_version("$Revision: 1.49 $");
  script_cvs_date("$Date: 2015/10/13 15:19:31 $");

  script_cve_id("CVE-2000-0505", "CVE-2001-0729");
  script_bugtraq_id(1284);
  script_osvdb_id(342, 9701);
  
  script_name(english:"Apache for Windows Multiple Forward Slash Directory Listing");
  script_summary(english:"Send multiple /'s to Windows Apache Server");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the list of the contents of the remote
directory." );
  script_set_attribute(attribute:"description", value:
"Certain versions of Apache for Win32 have a bug wherein remote users
can list directory entries.  Specifically, by appending multiple /'s
to the HTTP GET command, the remote Apache server will list all files
and subdirectories within the web root (as defined in httpd.conf)." );
  script_set_attribute(attribute:"solution", value:
"Upgrade to the most recent version of Apache at www.apache.org" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2000/06/13");
  script_set_attribute(attribute:"vuln_publication_date", value: "2000/05/30");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"Copyright 2000-2015 John Lampe....j_lampe@bellsouth.net");
  script_dependencies("http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_keys("www/apache", "Settings/ThoroughTests");
  script_require_ports("Services/www", 80);
  exit(0);
}



#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( ! thorough_tests ) exit(1, "This plugin only runs if the 'Perform thorough tests' setting is enabled.");


global_var port;

function find_index(k) {
    local_var buf, incoming, q, report;

    if(k < 16)k = 17;
    for (q=k-16; q<k; q=q+1) {
            buf = http_get(item:crap(length:q, data:"/"), port:port);
	    incoming = http_keepalive_send_recv(port:port, data:buf);
	    if ( incoming == NULL ) exit(0);
            if ("Index of /" >< incoming)  {
		report = '\nThe contents of / are :\n' + incoming;
                security_warning(port:port, extra:report);
                exit(0);
            }
         
    }
    exit(0, "The web server on port "+port+" is not affected.");
}




port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( ! banner ) exit(1, "No HTTP banner on port "+port+".");

if ( "Apache" >!< banner  ) exit(0, "The web server on port "+port+" is not Apache.");
if ( !thorough_tests && "Win32" >!< banner )  exit(0, "The web server on port "+port+" is not Apache for Windows.");



req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(1, "The web server on port "+port+" failed to answer.");
if ( "Index of /" >< res ) exit(0, "Web index for / on port "+port+".");

if(get_port_state(port)) {
    for (i=2; i < 512; i=i+16) {
            buf = http_get(item:crap(length:i, data:"/"), port:port);
	    incoming = http_keepalive_send_recv(port:port, data:buf);
	    if(incoming == NULL)exit(1, "The web server on port "+port+" failed to answer.");
            if ("Forbidden" >< incoming) {
                  find_index(k:i);
            }
        
    }
}
