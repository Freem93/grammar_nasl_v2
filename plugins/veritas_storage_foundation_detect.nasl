#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31861);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/08/23 21:19:09 $");

  script_name(english:"Symantec Storage Foundation Scheduler Service Detection");
  script_summary(english:"Detects Veritas Scheduler Service");

 script_set_attribute(attribute:"synopsis", value:
"A Veritas Scheduler Service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a Veritas Scheduler Service.  Symantec
Storage Foundation for Windows is a commercial storage and volume
management solution from Symantec, and the Scheduler Service is used
to schedule backup jobs." );
  # http://www.symantec.com/business/products/overview.jsp?pcid=2245&pvid=31_1
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed8ee243" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/15");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:veritas_storage_foundation");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports(4888);

  exit(0);
}

include ("global_settings.inc");
include ("misc_func.inc");
include ("byte_func.inc");
include ("smb_func.inc");

port = 4888;

if (!get_port_state(port))
  exit(0);

soc = open_sock_tcp(port);
if (!soc)
  exit(0);

req = ntlmssp_negotiate_securityblob();
len = strlen(req);

data = 
	mkdword(len) +
	mkdword(0x10) +
	mkdword(0) +
        "{c15f4527-3d6c-167b-f9c2-ca3908613b5a}" +
	mkbyte(0) +
	req;


send(socket:soc, data:data);
buf = recv(socket:soc, length:4096);
code = getdword(blob:buf, pos:4);

if ("{C15F4527-3D6C-167B-F9C2-CA3908613B5A}" >< buf && ("-2147220973" >< buf || '\xa1\x81\xa4\x30\x81\xa1' >< buf || code == 0x20) )
{
 set_kb_item (name:"VERITAS/VeritasSchedulerService", value:port);
 register_service (port:port, proto:"vss");
 security_note(port);
}
