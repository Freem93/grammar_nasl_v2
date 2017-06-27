#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10424);
  script_version ("$Revision: 1.19 $");

  script_cve_id("CVE-2000-0448");
  script_bugtraq_id(1253);
  script_osvdb_id(326);

  script_name(english:"NAI WebShield SMTP GET_CONFIG Information Disclosure");
  script_summary(english:"Determines if the remote NAI WebShield SMTP Management trusts us");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote management service is prone to information disclosure.'
  );

  script_set_attribute( attribute:'description',  value:
"The remote NAI WebShield SMTP Management tool gives away its 
configuration when it is issued the command :

   GET_CONFIG

This may be of some use to an attacker to gain more knowledge about 
this system."  );

  script_set_attribute(
    attribute:'solution',
    value:
"Filter incoming traffic to this port. You may also restrict
the set of trusted hosts in the configuration console :
  - go to the 'server' section
  - select the 'trusted clients' tab
  - and set the data accordingly"
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/05/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/05/25");
 script_cvs_date("$Date: 2011/03/11 21:52:36 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 script_dependencie("find_service1.nasl");
 script_require_ports(9999);
 script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");
 exit(0);
}

#
# The script code starts here
#

port = 9999;
if(get_port_state(port))
{
   soc = open_sock_tcp(port);
   if(soc)
   {
     req = string("GET_CONFIG\r\n");
     send(socket:soc, data:req);
     r = recv(socket:soc, length:2048);
     close(soc);
     if("SMTP_READ_PORT" >< r)
     {
       set_kb_item(name:"nai_webshield_management_agent/available", value:TRUE);
       security_warning(port);
     }
   }
}
