#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22196);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2006-3838");
  script_bugtraq_id(19424);
  script_osvdb_id(27529);
  script_xref(name:"Secunia", value:"21211");

  script_name(english:"eIQnetworks Enterprise Security Analyzer Monitoring.exe Multiple Command Overflow");
  script_summary(english:"Tries to crash ESA monitoring agent with a long argument to QUERYMONITOR");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is vulnerable to a remote
buffer overflow attack." );
 script_set_attribute(attribute:"description", value:
"The version of eIQnetworks Enterprise Security Analyzer, Network
Security Analyzer, or one of its OEM versions installed on the remote
host contains a buffer overflow in its Monitoring Agent service. 
Using a long argument to a command, an unauthenticated, remote attacker
may be able to leverage this issue to execute arbitrary code on the
affected host with LOCAL SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.tippingpoint.com/security/advisories/TSRT-06-07.html" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Aug/218" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Enterprise Security Analyzer 2.1.14 / Network Security
Analyzer 4.5.4 / OEM software 4.5.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'eIQNetworks ESA Topology DELETEDEVICE Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/07/25");
 script_cvs_date("$Date: 2017/02/23 16:41:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");
  script_dependencies("esa_monitoring_detect.nasl");
  script_require_ports("Services/esa_monitoring", 10626);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc: "esa_monitoring", default: 10626, exit_on_fail: 1);

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

  send(socket:soc, data:string("QUERYMONITOR&", crap(500), "&&&"));
  res = recv(socket:soc, length:64);
  close(soc);

  # If we didn't get a response...
  if (isnull(res)) 
  {
    # Try to reconnect.
    if (service_is_dead(port: port, exit: 1) > 0)
      security_hole(port);
  }

