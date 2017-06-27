#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10085);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2014/05/26 00:06:13 $");

 script_cve_id("CVE-1999-0079");
 script_bugtraq_id(271);
 script_osvdb_id(958);
 script_xref(name:"Secunia", value:"14285");

 script_name(english:"Multiple Vendor FTP Multiple PASV Command Port Exhaustion DoS");
 script_summary(english:"Determines if a PASV DoS is feasible");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a remote denial of service
vulnerability.");
script_set_attribute(attribute:"description", value:
"The remote FTP server allows users to make any amount of PASV
commands, thus blocking the free ports for legitimate services and
consuming file descriptors. An unauthenticated attacker could exploit
this flaw to crash the FTP service.");
script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c20a7602");
script_set_attribute(attribute:"solution", value:"Apply the patches as per the references.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/07/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);

 script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");

 script_family(english:"FTP");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login", "Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include('global_settings.inc');
include('misc_func.inc');
include('ftp_func.inc');


if (report_paranoia < 2) audit(AUDIT_PARANOID);

login = get_kb_item_or_exit("ftp/login");
password = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

if(ftp_authenticate(socket:soc, user:login, pass:password))
{
 port1 = ftp_pasv(socket:soc);
 for(i=0;i<40;i=i+1)port2 = ftp_pasv(socket:soc);
 if(port1 == port2){
	close(soc);
	exit(0);
	}
 if(port2){
	soc1 = open_sock_tcp(port1, transport:get_port_transport(port));
 	if(soc1>0){
		security_warning(port);
		close(soc1);
		}
	}
}
close(soc);
