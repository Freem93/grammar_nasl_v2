#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(20870);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_name(english:"LDAP Server Detection");
  script_summary(english:"Detects an LDAP server.");

  script_set_attribute(attribute:"synopsis", value:
"An LDAP server was detected on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a Lightweight Directory Access Protocol
(LDAP) server. LDAP is a protocol for providing access to directory
services over TCP/IP.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/LDAP");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 389);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("kerberos_func.inc");
include("ldap_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) 
{
  port = get_unknown_svc(389);
  if (!port) exit(0, "No unknown services left to identify.");
  ports = make_list(port);
}
else ports = make_list(389, 636, 3268, 3269);

foreach port (ports) 
{
 if (!get_port_state(port)) continue;
 soc = open_sock_tcp(port);
 if (!soc) continue;
 ldap_init(socket:soc);
 bind = ldap_bind_request();
 ret = ldap_request_sendrecv(data:bind);
 close(soc);
 if (!isnull(ret) && ret[0] == LDAP_BIND_RESPONSE)
 {
   # if channel is cleartext, we should probably
   # flag this for PCI
   if('TLS confidentiality required' >!< ret[1] && # you can force TLS on openldap
       get_port_transport(port) == ENCAPS_IP)
   {
     report = 'The remote LDAP server accepts cleartext authentication.';
     set_kb_item(name:"PCI/ClearTextCreds/" + port, value:report);
   }

  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"ldap");
  security_note(port);
 }
}
