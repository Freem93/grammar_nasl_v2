#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14645);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2004-1646");
  script_bugtraq_id(11071);
  script_osvdb_id(9391);
  script_xref(name:"Secunia", value:"12418");

  script_name(english:"Xedus Web Server Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server with a directory
traversal vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host runs Xedus Peer-to-Peer web server.  This version is 
vulnerable to directory traversal.  An attacker could send a specially 
crafted URL to view arbitrary files on the system." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d859f3a" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/30");
 script_cvs_date("$Date: 2015/09/24 23:21:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_summary(english:"Checks for directory traversal in Xedus");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
  script_dependencies("xedus_detect.nasl");
  script_family(english:"Peer-To-Peer File Sharing");
  script_require_ports("Services/www", 4274);
  exit(0);
}

# now the code

include("http_func.inc");

port = get_http_port(default:4274);
if ( ! get_kb_item("xedus/" + port + "/running")) exit(0);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"../../../../../boot.ini", port:port);
  send(socket:soc, data:buf);
  rep = http_recv(socket:soc);
  if(egrep(pattern:"\[boot loader\]", string:rep))
    security_warning(port);
  http_close_socket(soc);
 }
}
exit(0);
