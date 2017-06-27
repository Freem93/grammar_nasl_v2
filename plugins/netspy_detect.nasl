#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90254);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_name(english:"NetSpy Malware Services Detection");
  script_summary(english:"Detects the service port opened by NetSpy.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus detected a malicious service running on the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus detected a backdoor trojan known as NetSpy on the remote host.
A remote attacker can exploit this to have unrestricted remote control
over the system.");
  # https://www.symantec.com/security_response/attacksignatures/detail.jsp?asid=20198
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48ff472e");
  script_set_attribute(attribute:"solution", value:
"Remove the infection or restore the system from a known set of good
backups.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"malware", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_require_ports(7306);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

package = 'netspy nessus nessus nessus nessus nessus\r\n\r\n';

netspy_sock = open_sock_tcp("7306");
if (netspy_sock <= 0)
{
  exit(0, "Failed to establish a connection to port 7306.");
}

send(socket:netspy_sock, data:package);
res = recv(socket:netspy_sock, length:1024);

close(netspy_sock);

if ( !isnull(res) && len(res) == 32 && eregmatch(string:res, pattern:"^54 bytes.*"))
{
  report = "NetSpy RAT service detected running on the system.";
  security_hole(port:7306, extra:report);
}
else
{
  exit(0, "Not infected.");
}
