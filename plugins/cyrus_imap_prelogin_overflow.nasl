#
# This script was written by Paul Johnston of Westpoint Ltd <paul@westpoint.ltd.uk>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, desc enhance (7/08/09)


include("compat.inc");

if (description)
{
 script_id(11196);
 script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2016/10/10 15:57:04 $");

 script_osvdb_id(55701);
  
 script_name(english:"Cyrus IMAP Server login Command Remote Overflow");
 script_summary(english:"Checks for a pre-login buffer overrun in Cyrus IMAPd");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a remote integer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote Cyrus IMAP server is vulnerable to
a pre-login buffer overrun. 
 
An attacker without a valid login could exploit this, and would be 
able to execute arbitrary commands as the owner of the Cyrus process.
This would allow full access to all users' mailboxes.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Dec/17");
 script_set_attribute(attribute:"solution", value:
"If possible, upgrade to an unaffected version. However, at 
the time of writing no official fix was available. There is a source 
patch against 2.1.10 in the Bugtraq report.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/12/20");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:cmu:cyrus_imap_server");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Paul Johnston, Westpoint Ltd");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl");	       		     
 script_require_ports("Services/imap", 143);
 script_exclude_keys("imap/false_imap");

 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/imap");
if(!port) port = 143;

key = string("imap/banner/", port);
banner = get_kb_item(key);
if(!banner)
{
  if(get_port_state(port))
  {
    soc = open_sock_tcp(port);
    if(soc)
    { 
      banner = recv_line(socket:soc, length:255);
      close(soc);
    }
  }
}
if(!banner) exit(0);

if (("Cyrus IMAP4" >< banner) && egrep (pattern:"^\* OK.*Cyrus IMAP4 v([0-9]+\.[0-9]+\.[0-9]+.*) server ready", string:banner))
{
  version = ereg_replace(pattern:".* v(.*) server.*", string:banner, replace:"\1");
  set_kb_item (name:"imap/" + port + "/Cyrus", value:version);

  if(egrep(pattern:"^(1\..*|2\.0\..*|2\.1\.[1-9][^0-9]|2\.1\.10)[0-9]*$", string:version))
  {
    security_hole(port);
  }    
} 
