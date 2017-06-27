#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10408);
 script_version ("$Revision: 1.24 $");

 script_cve_id("CVE-2000-0412");
 script_bugtraq_id(1186);
 script_osvdb_id(310, 11875);

 script_name(english:"Gnapster Absolute Path Name Request Arbitrary File Access");
 script_summary(english:"Detect the presence of a Napster client clone");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a P2P file sharing application installed." );
 script_set_attribute(attribute:"description", value:
"An insecure Napster clone (e.g. Gnapster or Knapster) is running on
the remote computer, which allows an intruder to read arbitrary files
on this system, regardless of the shared status of the files." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/May/132" );
 script_set_attribute(attribute:"solution", value:
"If this is Gnapster, upgrade to version 1.3.9 or later, as this
reportedly fixes the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/05/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/05/10");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Peer-To-Peer File Sharing");
 script_require_keys("Services/napster");
 script_require_ports("Services/napster", 6699);
 script_dependencies("find_service1.nasl");
 exit(0);
}

#
# The script code starts here
#

 port = get_kb_item("Services/napster");
 if (!port) port = 6699;

 if (get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if (soc)
  {
    r = recv(socket:soc, length:1024);
    send(socket:soc, data:"GET");
    str = string("Nessus ", raw_string(0x22), "\\etc\\passwd", raw_string(0x22), " 9");
    send(socket:soc, data:str);
    r = recv(socket:soc, length:4096);
    if("root:" >< r)
    {
     security_hole(port);
    }
    close(soc);
  }
 }
