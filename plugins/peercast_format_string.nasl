#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18417);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-1806");
  script_bugtraq_id(13808);
  script_osvdb_id(16906);

  script_name(english:"PeerCast URL Error Message Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote peer-to-peer application is affected by a format string
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of PeerCast installed on the remote host suffers from a
format string vulnerability.  An attacker can issue requests
containing format specifiers that will crash the server and
potentially permit arbitrary code execution subject to privileges of
the user under which the affected application runs." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00077-05282005" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/May/334" );
 # http://web.archive.org/web/20071106134310/http://www.peercast.org/forum/viewtopic.php?p=11596
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0438223" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PeerCast 0.1212 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/28");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for format string vulnerability in PeerCast");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Peer-To-Peer File Sharing");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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

        if (iver[0] == 0 && iver[1] < 1212) vuln = TRUE;
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
      if (http_is_dead(port:port)) exit(1, "The web server is dead");

      # Try to crash it.
      r = http_send_recv3(method:"GET",item:"/html/en/index.htm%n", port:port);
      # There's a problem if the server's down.
      if (http_is_dead(port:port))
      {
        security_hole(port);
        exit(0);
      }
    }
  }
}
