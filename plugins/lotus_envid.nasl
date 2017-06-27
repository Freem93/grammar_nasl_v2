#
# (C) Tenable Network Security, Inc.
#

# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# and was modified and tested by Vanja Hrustic <vanja@relaygroup.com>

include("compat.inc");

if(description)
{
 script_id(10543);
 script_version ("$Revision: 1.31 $");
 script_cvs_date("$Date: 2017/05/09 15:19:41 $");

 script_cve_id("CVE-2000-1047");
 script_bugtraq_id(1905);
 script_osvdb_id(442);
 
 script_name(english:"Lotus Domino SMTP ENVID Variable Handling RCE");
 script_summary(english:"Determines if the remote Domino server is vulnerable to a buffer overflow.");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SMTP server is affected by a remote code execution
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The Lotus Domino SMTP server running on the remote host is affected
by a buffer overflow condition due to improper validation of input
to the ENVID variable within a MAIL FROM command. An unauthenticated,
remote attack can exploit this, via a overly long ENVID value, to
cause a denial of service condition or possibly the execution of
arbitrary code.");
  # http://www-10.lotus.com/ldd/fixlist.nsf/5c087391999d06e7852569280062619d/14a17267e64d687685256a85007381ea?OpenDocument&Highlight=0,CDOY4GFP35
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34705b38");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Lotus Notes/Domino version 5.0.6 or later. This reportedly
fixes the vulnerability.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:W/RC:X");

 script_set_attribute(attribute:"vuln_publication_date", value: "2000/11/03");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/11/06");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:lotus:domino_enterprise_server");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"SMTP problems");

 script_copyright(english:"This script is Copyright (C) 2000-2017 Tenable Network Security, Inc.");

 script_dependencie("smtpserver_detect.nasl", "smtp_settings.nasl");
 script_require_ports("Services/smtp", 25);

 exit(0);
}

#
# The script code starts here
#

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if(!port)port = 25;

if(get_port_state(port))
{
  soc = open_sock_tcp(port);
  if(soc)
  {
    r = smtp_recv_banner(socket:soc);
    if(!r)exit(0);
    
    if("omino" >< r)
    {
    domain = get_kb_item("Settings/third_party_domain");
    if(!domain) domain = "nessus.org";

    req = string("HELO ", domain, "\r\n");
    send(socket:soc, data:req);
    r  = recv_line(socket:soc, length:4096);

    req = string("MAIL FROM: <nessus@", domain, "> ENVID=", crap(300), "\r\n");
    send(socket:soc, data:req);
    r = recv_line(socket:soc, length:4096);

    if(ereg(pattern:"^250 ", string:r))
        security_hole(port);
    }
    close(soc);
   }
}
