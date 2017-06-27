#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29726);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2007-6454");
  script_bugtraq_id(26899);
  script_osvdb_id(40250);

  script_name(english:"PeerCast servhs.cpp handshakeHTTP Function SOURCE Request Remote Overflow");
  script_summary(english:"Checks for overflow in PeerCast web server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of PeerCast installed on the remote host fails to check
the length of user-supplied data in its 'handshakeHTTP' function in
'servhs.cpp' before copying it to the 'loginPassword' and 'loginMount'
heap-based buffers.  An unauthenticated attacker can leverage this
issue to crash the affected application or execute arbitrary code on
the remote host, subject to the privileges under which PeerCast
operates." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/485199/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PeerCast version 0.1218 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/18");
 script_cvs_date("$Date: 2012/12/13 23:15:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:peercast:peercast");
script_end_attributes();


  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Peer-To-Peer File Sharing");
  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
  script_dependencies("peercast_installed.nasl");
  script_require_keys("PeerCast/installed");
  script_require_ports("Services/www", 7144, 7145);

  exit(0);
}


if (!get_kb_item("PeerCast/installed")) exit(0);

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


list = get_kb_list("PeerCast/*/version");
if (isnull(list)) exit(0);

foreach key (keys(list))
{
  port = key - "PeerCast/" - "/version";
  ver = list[key];

  if (get_port_state(port))
  {
    # If safe checks are enabled...
    if (safe_checks())
    {
      # Check the version.
      vuln = FALSE;

      if (ver =~ "^[0-9]\.[0-9]+$")
      {
        iver = split(ver, sep:'.', keep:FALSE);
        for (i=0; i<max_index(iver); i++)
          iver[i] = int(iver[i]);

        if (iver[0] == 0 && iver[1] < 1218) vuln = TRUE;
      }
      else if (report_paranoia > 1) vuln = TRUE;

      if (vuln)
      {
       report = string(
          "According to its Server response header, the version of PeerCast on the\n",
          "remote host is :\n",
          "\n",
          "  ", ver, "\n"
        );
        security_hole(port:port, extra:report);
        break;
      }
    }
    # Otherwise...
    else
    {
      # Make sure the server's up.
      if (http_is_dead(port:port)) exit(1);

      # Try to crash it.
      req = string("SOURCE ", crap(data:"A", length:165), "\r\n\r\n");
      r = http_send_recv_buf(port:port, data: req);

      # There's a problem if the server's down.
      if (http_is_dead(port:port))
      {
        security_hole(port);
        exit(0);
      }
    }
  }
}
