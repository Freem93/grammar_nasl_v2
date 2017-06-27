#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(16139);
 script_version("$Revision: 1.10 $");
 script_bugtraq_id(12240);
 script_osvdb_id(12896);

 script_name(english:"POP Password Changer (poppassd_pam) Arbitrary User Remote Password Modification");
 
 script_set_attribute(attribute:"synopsis", value:
"Passwords can be changed on the remote POP server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running POP Password Changer, a server to change
POP user's passwords.

According to the version number, the remote software is vulnerable
to an unauthorized access. An attacker, exploiting this flaw, will
be able to change user's password." );
 script_set_attribute(attribute:"solution", value:
"Ensure that you are running a patched or more recent version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/11");
 script_cvs_date("$Date: 2011/03/11 21:52:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines if POP Password Changer is vulnerable to access control bypass.");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english: "Misc.");
 script_require_ports(106, "Services/pop3pw");
 script_dependencies('find_service1.nasl', 'find_service_3digits.nasl');
 exit(0);
}

port = get_kb_item("Services/pop3pw");
if (! port) port = 106;

if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

r = recv(socket:soc, length:4096);
if (!r) exit (0);

if (egrep(pattern:"^200 .*poppassd v(0\..*|1\.0) hello, who are you", string:r))
 {
 security_hole(port);
 exit(0);
 }
