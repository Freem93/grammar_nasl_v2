#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(35710);
 script_version("$Revision: 1.8 $");
 script_cvs_date("$Date: 2016/10/13 15:15:41 $");

 script_name(english:"Internet Gateway Device WAN Interface UPnP Access");
 script_summary(english:"Reconfigure IGD router from outside.");

 script_set_attribute(attribute:"synopsis", value:
"The remote IGD router can be configured on its WAN interface.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to add 'port mappings' to the remote IGD router by
sending a SOAP request to its external interface.");
 script_set_attribute(attribute:"solution", value:
"Restrict external access to this device.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

 script_dependencie("upnp_add_port_mapping.nasl", "upnp_external_ip_addr.nasl");
 script_require_keys("upnp/igd_add_port_mapping");

 exit(0);
}

include('global_settings.inc');
include('network_func.inc');
include('misc_func.inc');
include('audit.inc');

get_kb_item_or_exit('upnp/igd_add_port_mapping');
extip = get_kb_item_or_exit('upnp/external_ip_addr');
if (!isnull(extip))
{
  if (get_host_ip() == extip)
  {
    security_report_v4(port:0, severity:SECURITY_WARNING,
                       extra:"The remote IGD router can be configured from the WAN side.");
  }
  else audit(AUDIT_HOST_NOT, 'affected');
}
else
{
  if (!is_private_addr() && ! islocalnet())
  {
    security_report_v4(port:0, severity:SECURITY_WARNING,
                       extra:
                        '** Nessus relied on the fact that this is a public address.\n' +
                        '** If the internal address of this router is public, disregard this alert.\n');
  }
  else audit(AUDIT_HOST_NOT, 'affected');
}
