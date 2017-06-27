#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10422);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");

 script_cve_id("CVE-2000-0446");
 script_bugtraq_id(1252);
 script_osvdb_id(324);

 script_name(english:"MBDMS Database Server Long String Remote Overflow");
 script_summary(english:"Checks the remote MDBMS version");

 script_set_attribute(attribute:"synopsis", value:"The remote database server has a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a beta version of
MDBMS. It is very likely this version has a remote buffer overflow
vulnerability. A remote attacker could exploit this to crash the
service, or execute arbitrary code.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/May/279");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/05/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/10/18");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");

 script_require_keys("Settings/ParanoidReport");
 script_require_ports(2223, 2224);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 2224;
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc){
	port = 2223;
	if ( get_port_state(port) )
	 {
	 soc = open_sock_tcp(port);
	 if(!soc)exit(0);
	 }
	else exit(0);
	}

r = recv_line(socket:soc, length:1024);
close(soc);
if(ereg(pattern:"^.*MDBMS V0\..*", string:r))
{
security_hole(port);
}


