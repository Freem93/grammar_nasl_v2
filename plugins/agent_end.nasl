# 
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( !defined_func("report_xml_tag") ) exit(0);

if(description)
{
 script_id(92756);
 script_version ("$Revision: 1.2 $");
 script_cvs_date("$Date: 2017/01/31 22:24:23 $");

 script_name(english:"Set Reporting Items for Nessus Agents");
 script_summary(english:"Sets reporting items for Nessus agents.");

 script_set_attribute(attribute:"synopsis", value:
"This internal plugin adds an XML tag in the report about the agent
host.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to determine information about the agent host. This
plugin, which does not show up in the report, reports information
for this host as an XML tag in the Nessus reports.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/05");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"all");
 script_end_attributes();

 script_category(ACT_END);
 script_family(english:"Settings");
 script_dependencies("netstat_parse.nasl", "ssh_get_info.nasl", "wmi_list_interfaces.nbin",
                     "wmi_system_hostname.nbin");

 script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

 exit(0);
}

include("agent.inc");
include("misc_func.inc");

if (!agent())
  exit(0, "This plugin is only for Nessus agents.");

ip_addr = agent_get_ip();
if(empty_or_null(ip_addr)) ip_addr = get_host_ip();

if(!empty_or_null(ip_addr))
  report_xml_tag(tag:"host-ip", value:ip_addr);
