#
# Copyright (C) 2005 Secure Computer Group. University of A Coruna
#
# This script was written by Javier Munoz Mellid <jm@udc.es>
#
# This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title, removed VDB refs that don't apply (6/17/09)
# - Added CPE and updated copyright (08/16/2012)

include("compat.inc");

if(description)
{
 script_id(18184);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2012/08/16 22:15:22 $");

 script_name(english:"Kerio Mailserver Admin Service Detection");

 script_set_attribute(attribute:"synopsis", value:
"The administrative interface of a mail server is listening on
this port." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running the Kerio Admin MailServer
Admin Service on this port." );
 script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/02");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:kerio:kerio_mailserver");
script_end_attributes();


 script_summary(english:"Determines if Kerio Mailserver is installed");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2012 Javier Munoz Mellid");
 script_family(english:"Service detection");
 script_require_ports(44337);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

function kms_isWeakAdminProtocol(port)
{
  local_var soc, vuln, i, s, r;

  soc = open_sock_tcp(port, transport: ENCAPS_TLSv1);

  if (!soc) return 0;

  vuln = 1;

  for(i=0;i<5;i=i+1) {

        s = raw_string(0x01);
        send(socket:soc, data: s);

        if (!soc) vuln = 0;

        r = recv(socket: soc, length: 16);

        if (isnull(r)||(strlen(r)!=2)||(ord(r[0])!=0x01)||(ord(r[1])!=0x00))
        {

                vuln = 0;
                break;

        }

  }

  close(soc);

  if (vuln)
        return 1;
  else
        return 0;
}

port = 44337;           # default kms port

if (! get_port_state(port)) exit(0);

if (kms_isWeakAdminProtocol(port:port))
{
  register_service(port:port, proto:"kerio_mailserver_admin");
  security_note(port);
}
  
exit(0);
