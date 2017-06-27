#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(38789);
  script_version ("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/01/25 01:19:09 $");
 
  script_name(english:"QMTP Open Relay");
 
  script_set_attribute(attribute:"synopsis", value:
"An open QMTP relay is running on this port." );
  script_set_attribute(attribute:"description", value:
"The QMTP/QMQP server that is running on this port allows relaying. 
Make sure it rejects connections from Internet so that it cannot be
used use as an open relay.  Otherwise, it may be blacklisted by RBLs
or overloaded by spam." );
  script_set_attribute(attribute:"solution", value:
"Restrict access to this service or disable it if it is not used." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/15");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_summary(english: "Sends mail through QMTP/QMQP");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
  script_family(english:"Misc.");
  script_dependencie("qmtp_detect.nasl");
  script_require_ports("Services/QMTP", "Services/QMQP");

  exit(0);
}

####

include("global_settings.inc");
include("misc_func.inc");
include("network_func.inc");

if (is_private_addr(addr: get_host_ip()) ||
    is_private_addr(addr: this_host())) exit(0);

ports = get_kb_list("QMTP/relay/*");
if (isnull(ports)) exit(0);

foreach port (ports) security_hole(port);
