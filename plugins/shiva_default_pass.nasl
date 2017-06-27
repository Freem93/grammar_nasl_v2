#
# This script was written by Stefaan Van Dooren <stefaanv@kompas.be>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable
# - only attempt to login if the policy allows it (10/25/11 and  6/2015)
# - Updated to use compat.inc, added CVSS score (11/20/2009)
# - Updated to use global_settings.inc (6/2015)


include("compat.inc");

if (description)
{
  script_id(10500);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/09/24 16:49:07 $");

  script_cve_id("CVE-1999-0508");
  script_osvdb_id(399);

  script_name(english:"Shiva Integrator Default Password");
  script_summary(english:"Attempts to log in to the remote host.");

  script_set_attribute(attribute:"synopsis", value:
"The remote router can be accessed with default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote Shiva router uses the default password. 
This means that anyone who has (downloaded) a user manual can 
telnet to it and reconfigure it to lock you out of it, and to 
prevent you to use your internet connection.");
  script_set_attribute(attribute:"solution", value:
"telnet to this router and set a different password immediately." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SNMP Community Scanner');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/08/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
 
  script_copyright(english:"This script is Copyright (C) 2000-2015 Stefaan Van Dooren");

  script_require_ports(23);
  script_exclude_keys("global_settings/supplied_logins_only");
 
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");

port = 23;
if(get_port_state(port))
{
	if (supplied_logins_only) exit(0, "Policy is configured to prevent trying default user accounts");
	soc = open_sock_tcp(port);
	if(soc)
	{
		data = string("hello\n\r");
		send(data:data, socket:soc);
		buf = recv(socket:soc, length:4096);
		if ("ntering privileged mode" >< buf)
			security_hole(port);
		close(soc);
	}
}

