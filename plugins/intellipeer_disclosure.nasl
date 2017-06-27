#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(14829);
  script_version ("$Revision: 1.15 $");
  script_cve_id("CVE-2004-2150");
  script_bugtraq_id(11257);
  script_osvdb_id(10349);

  script_name(english:"Intellipeer POP3 Server User Account Enumeration");
  script_summary(english:"Checks for a flaw in Intellipeer pop3");
  script_set_attribute(
    attribute:'synopsis',
    value:"The remote server is vulnerable to information disclosure."
  );

  script_set_attribute(attribute:'description', value:
"The remote POP3 server (probably intellipeer pop3 server) is
vulnerable to an account enumeration issue.

If an attacker attempts to log into the remote host by submitting a
bogus username, then the server will reply with a specific error
message if the account is nonexistent, while it will reply with
another message if the account exists.

An attacker may use this flaw to set up a brute-force attack against
the remote server to obtain a list of valid user names and accounts."
  );

  script_set_attribute(
    attribute:'solution',
    value:"Upgrade to Intillipeer POP3 server version 1.02 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:"http://www.nettica.com/Downloads/Default.aspx"
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/27");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");
  script_dependencie("find_service1.nasl");
  script_require_ports("Services/pop3", 110);
  exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");
include("pop3_func.inc");

port = get_kb_item("Services/pop3");
if(!port) port = 110;
if ( ! get_port_state(port) ) exit(0);

banner = get_pop3_banner(port:port);
if ( ! banner || "POP3 server ready <" >!< banner ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

banner = recv_line(socket:soc, length:4096);
if ( ! banner ) exit(0);
send(socket:soc, data:'USER nessus' + rand() + '\r\n');
rep = recv_line(socket:soc, length:4096);
if ( ! rep ) exit(0);
if (egrep(pattern:"^-ERR nessus[0-9]* unknown account", string:rep) )
{
 security_warning(port);
}
