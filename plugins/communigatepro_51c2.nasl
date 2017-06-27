#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21917);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-3477");
  script_bugtraq_id(18770);
  script_osvdb_id(26954);

  script_name(english:"CommuniGate Pro POP Service Empty Inbox Remote DoS");
  script_summary(english:"Checks version of CommuniGate Pro");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of CommuniGate Pro running on the
remote host will crash when certain mail clients try to open an empty
mailbox." );
 script_set_attribute(attribute:"see_also", value:"http://www.stalker.com/CommuniGatePro/History.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CommuniGate Pro 5.1c2 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/07/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/30");
 script_cvs_date("$Date: 2012/06/14 00:42:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:communigate:communigate_pro_core_server");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");
  script_dependencies("find_service_3digits.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/pop3", 110);

  exit(0);
}


include("pop3_func.inc");


port = get_kb_item("Services/pop3");
if (!port) port = 110;
if (!get_port_state(port)) exit(0);


# Check CommuniGate Pro's banner.
banner = get_pop3_banner(port:port);
if (
  banner &&
  "CommuniGate Pro POP3 Server" >< banner &&
  egrep(pattern:"CommuniGate Pro POP3 Server ([0-4]\.|5\.(0[^0-9]|1([ab][0-9]|c1)))", string:banner)
) security_warning(port);
