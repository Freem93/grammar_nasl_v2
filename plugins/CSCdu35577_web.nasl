#
# This script was written by Michael J. Richardson <michael.richardson@protiviti.com>
#
# Changes by Tenable:
# - Added OSVDB refs, updated copyright (1/20/09)
# - Added CVSS2 scores, revised desc.
# - Title tweak, formatting (10/29/09)
# - Fixed typo in the solution (03/05/14)


include("compat.inc");

if(description)
{
  script_id(14718);
  script_version ("$Revision: 1.16 $");
  script_cve_id("CVE-2002-1094");
  script_bugtraq_id(5624);
  script_osvdb_id(8909);

  script_name(english:"Cisco VPN 3000 Concentrator Multiple Service Banner System Information Disclosure (CSCdu35577 HTTP Check)");

 script_set_attribute(attribute:"synopsis", value:
"The remote VPN concentrator reveals application layer banners." );
 script_set_attribute(attribute:"description", value:
"The remote VPN concentrator gives out too much information in 
application layer banners. An incorrect page request provides 
the specific version of software installed. This vulnerability 
is documented as Cisco bug ID CSCdu35577." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2dd6759" );
 script_set_attribute(attribute:"solution", value:
"Apply vendor-supplied patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/09/03");
 script_cvs_date("$Date: 2014/08/11 19:44:18 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value: "cpe:/o:cisco:ios");
script_end_attributes();

 script_summary(english:"Checks web interface for Cisco bug ID CSCdu35577");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2014 Michael J. Richardson");
 script_family(english:"CISCO");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include ("global_settings.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))
  exit(0);


req = http_get(item:"/this_page_should_not_exist.htm", port:port);
res = http_keepalive_send_recv(port:port, data:req);

if ( res == NULL ) 
  exit(0);

if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 ", string:res) && "<b>Software Version:</b> >< res" && "Cisco Systems, Inc./VPN 3000 Concentrator Version" >< res)
  {
    security_warning(port:port);
    exit(0);
  }
