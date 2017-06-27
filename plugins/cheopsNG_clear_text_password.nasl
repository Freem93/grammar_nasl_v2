#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(20162);
 script_version ("$Revision: 1.13 $");
 script_cvs_date("$Date: 2016/01/05 18:44:51 $");

 script_name(english:"Cheops-ng Cleartext Authentication Information Disclosure");
 script_summary(english: "Cheops-ng agent uses cleartext passwords.");

 script_set_attribute(attribute:"synopsis", value:
"The remote Cheops-ng agent is affected by an information disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"A Cheops-ng agent is running on the remote host, and it is configured
to allow unencrypted connections. It is, therefore, affected by an
information disclosure vulnerability due to passwords being
transmitted in cleartext. A user with a valid account on the remote
host can connect to the agent and use it to map your network, port
scan machines, and identify running services. In addition, it is
possible to brute-force login/passwords on the remote host using this
agent.");
 script_set_attribute(attribute:"see_also", value:"http://cheops-ng.sourceforge.net/");
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/projects/cheops-ng/");
 script_set_attribute(attribute:"solution", value:
"Configure Cheops-ng to run on top of SSL or block this port from
outside communication if you want to further restrict the use of
Cheops-ng.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/08");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Misc.");

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

 script_dependencie("cheopsNG_detect.nasl");
 script_require_keys("cheopsNG/password");
 exit(0);
}

port = get_kb_item("cheopsNG/password");
if (port && get_port_transport(port) == ENCAPS_IP )
{
  pci_report = 'The remote Cheops-ng service on port ' + port + ' accepts cleartext logins.';
  set_kb_item(name:"PCI/ClearTextCreds/" + port, value:pci_report);
  security_warning(port);
}
