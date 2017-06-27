#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11576);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2002-1562", "CVE-2003-0899");
 script_bugtraq_id(8924, 8906);
 script_osvdb_id(2729, 7359);
 script_xref(name:"SuSE", value:"SUSE-SA:2003:044");
 
 script_name(english:"thttpd Host Header Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to read arbitrary files from the remote 
system." );
 script_set_attribute(attribute:"description", value:
"The remote HTTP server allows anyone to browse the files on 
the remote host by sending HTTP requests with a Host: field 
set to '../../'." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to thttpd 2.23 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/06");
 script_cvs_date("$Date: 2016/11/23 20:42:24 $");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/10/31");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();
 
 script_summary(english:"thttpd flaw");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

res = http_send_recv3(method:"GET", item:"/", port:port);
if(isnull(res)) exit(1,"Null response to / request.");

list1 = NULL;
if("mode  links  bytes  last-changed  name" >< res[2]) { list1 = res[2]; }

res = http_send_recv3(method:"GET", item:"/", port:port,
           add_headers: make_array("Host", string(get_host_name(),"/.."))
      );
 
if(isnull(res)) exit(1,"Null response to second / request.");
 
if("mode  links  bytes  last-changed  name" >< res[2])
{
  if(!list1)security_warning(port);
  else 	
  {
    l = strstr(list1, string("\r\n\r\n"));
    m = strstr(res[2], string("\r\n\r\n"));
    #display(m);
    if(l != m)security_warning(port);
  }
}
