#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID
#


include("compat.inc");


if(description)
{
 script_id(10788);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-2001-1503");
 script_bugtraq_id(3457);
 script_osvdb_id(658);

 script_name(english:"Solaris in.fingerd Unused Accounts Disclosure");
 script_summary(english:"Enumerates users with finger");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote finger service has an information disclosure vulnerability."
 );
 script_set_attribute( attribute:"description",  value:
"The remote Solaris finger daemon will return a list of accounts that
have never been used when it receives the request :

  finger 'a b c d e f g h'@target

A remote attacker could use this information to guess which operating
system is running, or to mount further attacks on these accounts." );
 # https://web.archive.org/web/20051104210906/http://archives.neohapsis.com/archives/vulnwatch/2001-q4/0016.html
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?03f64d50"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Apply the relevant patches from Sun."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/10/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/10/22");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");

 script_dependencies("find_service1.nasl", "finger.nasl");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = string("a b c d e f g h\r\n");
  send(socket:soc, data:buf);
  data = recv(socket:soc, length:65535);
  close(soc);

  if(("daemon" >< data) && ("root" >< data) && ("nobody" >< data))
  {
    report = string(
      "\n",
      "Nessus was able to retrieve a list of the following users :\n\n",
      data, "\n"
    );
    security_warning(port:port, extra:report);
  }
 }
}
