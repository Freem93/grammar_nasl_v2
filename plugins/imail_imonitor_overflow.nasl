#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10124);
 script_version("$Revision: 1.39 $");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");

 script_cve_id("CVE-1999-1046", "CVE-2000-0056");
 script_bugtraq_id(502, 504, 506, 914);
 script_osvdb_id(1190, 9005);

 script_name(english:"IMail IMonitor Service Remote Overflow");
 script_summary(english:"IMail's IMonitor buffer overflow.");

 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running IMail IMAP server.The installed
version is reportedly affected by a buffer overflow vulnerability in
the IMonitor. An attacker could exploit this flaw in order to cause
a denial of service or potentially execute arbitrary code subject to
the privileges of the affected service.");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=92038879607336&w=2");
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value:"1999/03/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_require_ports("Services/imonitor", 8181);
 script_dependencies("find_service1.nasl", "http_version.nasl");

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_service(svc:"imonitor", default:8181, exit_on_fail:TRUE);

banner = get_http_banner(port:port, exit_on_fail:TRUE);

if(egrep(pattern:"^Server: IMail_Monitor/([0-5]\.|6\.[01][^0-9])", string:banner))
	security_hole(port);
