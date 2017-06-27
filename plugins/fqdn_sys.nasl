#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if ( !defined_func("report_xml_tag") ) exit(0);

if(description)
{
 script_id(47557);
 script_version ("$Revision: 1.10 $");
 script_cvs_date("$Date: 2017/04/14 21:18:20 $");
 
 script_name(english:"Host Fully Qualified Domain Name (FQDN) Resolution (XML tag)");
 script_summary(english:"Performs a name resolution.");
 
 script_set_attribute(attribute:"synopsis", value:
"This internal plugin adds an XML tag in the report about the remote
host.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to resolve the fully qualified domain name (FQDN) of
the remote host. This plugin, which does not show up in the report,
writes the IP and FQDN of this host as an XML tag in the .nessus v2
reports.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value: "2011/07/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_SETTINGS);
 script_family(english:"Settings");
 
 script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

 exit(0);
}

include("agent.inc");
include("misc_func.inc");

if (agent())
{
  hostname = agent_fqdn();
  if (!empty_or_null(hostname))
  {
    replace_kb_item(name:"myHostName", value:hostname);
    set_kb_item(name:"Host/agent/FQDN", value:hostname);
  }
}

else
  hostname = get_host_name();

# This will never match for the agent
if ( hostname != get_host_ip() )
{
  if ( !TARGET_IS_IPV6 || tolower(hostname) !~ "^[0-9a-f]+:" )
    report_xml_tag(tag:"host-fqdn", value:hostname);
}

if (!agent())
  report_xml_tag(tag:"host-ip", value:get_host_ip());
