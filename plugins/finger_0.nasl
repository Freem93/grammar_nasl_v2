#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10069);
 script_version ("$Revision: 1.32 $");
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");
 script_cve_id("CVE-1999-0197");
 script_osvdb_id(60);

 script_name(english:"Finger 0@host Unused Account Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is prone to information disclosure." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a 'finger' service that suffers from an
information disclosure vulnerability.  Specifically, it allows an
unauthenticated attacker to display a list of accounts on the remote
host that have never been used.  This list can help an attacker to
guess the operating system type and also focus his attacks." );
 script_set_attribute(attribute:"solution", value:
"Filter access to this port, upgrade the finger server, or disable it
entirely." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");


 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1995/01/01");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Finger 0@host feature");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2013 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencies("find_service1.nasl", "finger.nasl");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");


port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  # Cisco
  data = recv(socket:soc, length:2048, timeout:5);
  if(data)exit(0);
  buf = string("0\r\n");
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:65535);
  close(soc);

  if (
    strlen(data) > 150 && 
    egrep(pattern:'(^|[ \t]+)(adm|bin|daemon|lp|sys)[ \t]', string:data)
  ) {
    if (report_verbosity > 0) {
      security_warning(port:port, extra: data);
    }
    else {
      security_warning(port:port);
    }
    set_kb_item(name:"finger/0@host", value:TRUE);
  }
 }
}
