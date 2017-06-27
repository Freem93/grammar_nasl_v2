#
# (C) Tenable Network Security, Inc.
#

# Refs:
#  Subject: APC 9606 SmartSlot Web/SNMP management card "backdoor"
#   From: Dave Tarbatt <bugtraq@always.sniffing.net>
#   To: bugtraq@securityfocus.com
#   Date: 16 Feb 2004 11:24:32 +0000
#


include("compat.inc");

if(description)
{
 script_id(12066);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2004-0311");
 script_bugtraq_id(9681);
 script_osvdb_id(3985);
 script_xref(name:"Secunia", value:"10905");
 
 script_name(english:"APC SmartSlot Web/SNMP Management Card Default Password");
 script_summary(english:"Logs into the remote host");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a default password set." );
 script_set_attribute(attribute:"description", value:
"The remote APC Smartslot Web/SNMP Management card ships with a default
username and password. An attacker can use this information to access
the remote APC device with any username and the factory password
'TENmanUFactOryPOWER'." );
 script_set_attribute(attribute:"see_also", value:"http://nam-en.apc.com/cgi-bin/nam_en.cfg/php/enduser/std_adp.php?p_faqid=3131&p_created=1077139129" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Feb/456" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Feb/512" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Feb/514" );
 script_set_attribute(attribute:"solution", value:
"Upgrade the firmware according to the APC recommendations." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/18");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

#
# The script code starts here : 
#

include('telnet_func.inc');
port = 23;
if(get_port_state(port))
{
   banner =  get_telnet_banner(port:port);
   if ( "User Name :" >!< buf ) exit(0);

   soc = open_sock_tcp(port);
   if(soc)
   {
      buf = telnet_negotiate(socket:soc);
      if ("User Name :" >< buf)
         {
            data = string("*\r\n");
            send(socket:soc, data:data);
            buf = recv_line(socket:soc, length:1024);
	    if ( "Password" >!< buf ) exit(0);
	    send(socket:soc, data:'TENmanUFactOryPOWER\r\n');
	    buf = recv(socket:soc, length:4096);
	    if ("Factory Menu" >< buf  ||
		"Final Functional Test" >< buf ) security_hole(port);
         }
    close(soc);
   }
}

