#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64701);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/02/20 14:24:08 $");

  script_name(english:"EMC Data Protection Advisor CXML Service Detection");
  script_summary(english:"Detects EMC CXML Service");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running an automated analysis and alerting system
for backup and replication infrastructure."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The CXML service for EMC Data Protection Advisor, an automated analysis
and alerting system for backup and replication infrastructure, was
detected on the remote host."
  );
  # http://www.emc.com/backup-and-recovery/data-protection-advisor/data-protection-advisor.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?022c5999");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:data_protection_advisor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl", "find_service2.nasl");
  script_require_ports("Services/unknown", 3916);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

is_vuln = FALSE;
port_list = make_list(3916);

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery"))
{
  additional_ports = get_kb_list("Services/unknown");
  if (!isnull(additional_ports))
    port_list = make_list(port_list, additional_ports);
}

port_list = list_uniq(port_list);

foreach port (port_list)
{
  if (!get_tcp_port_state(port)) continue;

  if (!service_is_unknown(port: port))
  {
    if (get_kb_item("Known/tcp/" + port) != "emc_cxml") continue;
  }

  soc = open_sock_tcp(port);
  if (!soc) continue;

  req = "58/58/UNB<CXMLREQUEST><GETSTATUSINFO></GETSTATUSINFO></CXMLREQUEST>";
  send(socket:soc, data:req);
  res = recv(socket:soc, length:1024);
  close(soc);

  if (
    "<CXMLRESULT>" >< res &&
    "<FORMATTED>" >< res &&
    "</FORMATTED>" >< res &&
    "<PRODUCT>DPA</PRODUCT>" >< res
  )
  {
    item = eregmatch(pattern:"<FORMATTED>([^<]+)</FORMATTED>", string:res);
    if (isnull(item)) continue;

    is_vuln = TRUE;

    register_service(ipproto:"tcp", proto:"emc_cxml", port:port);
    set_kb_item(name:"emc_cxml/version/" + port, value:item[1]);

    if (report_verbosity > 0)
    {
      report = '\n  Source  : ' + item[0] +
               '\n  Version : ' + item[1] + '\n';
      security_note(port:port, protocol:"tcp", extra:report);
    }
    else security_note(port);
  }
}

if (!is_vuln) exit(0, 'Nessus did not detect any remote EMC Data Protection CXML services.');
