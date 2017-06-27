#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17985);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2012/06/14 00:42:38 $");

  script_cve_id("CVE-2005-1007");
  script_bugtraq_id(13001);
  script_osvdb_id(15257);

  script_name(english:"CommuniGate Pro LISTS Module Malformed Multipart Message DoS");
  script_summary(english:"Checks for denial of service vulnerability in CommuniGate Pro LISTS module");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is prone to a denial of service attack." );
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CommuniGate Pro running on
the remote host has an unspecified denial of service vulnerability
arising from a flaw in the LISTS module.  An attacker may be able to
crash the server by sending a malformed multipart message to a list."
);
  script_set_attribute(attribute:"see_also", value:"http://www.stalker.com/CommuniGatePro/History43.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to CommuniGate Pro 4.3c3 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/06");
  script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/15");
  script_set_attribute(attribute:"plugin_type", value:"remote");
   script_set_attribute(attribute:"cpe",value:"cpe:/a:communigate:communigate_pro_core_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");
  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
  script_dependencies("smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);

  exit(0);
}


include("smtp_func.inc");


port = get_kb_item("Services/smtp");
if (!port) port = 25;
if (!get_port_state(port)) exit(0);
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);


banner = get_smtp_banner(port:port);
if ( banner &&
    egrep(
    string:banner, 
    pattern:"CommuniGate Pro ([0-3]|4\.[0-2]|4\.3([ab][0-9]|c[0-2]))"
  )
) security_warning(port);
