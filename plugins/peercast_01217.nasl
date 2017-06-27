#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(21041);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2006-1148");
  script_bugtraq_id(17040);
  script_osvdb_id(23777);

  script_name(english:"PeerCast procConnectArgs() Function URL Handling Remote Overflow");
  script_summary(english:"Checks version of PeerCast web server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server suffers from a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of PeerCast installed on the remote host copies the
supplied option string without limit into a finite-size buffer.  An
unauthenticated attacker can leverage this issue to crash the affected
application and possibly to execute arbitrary code on the remote host
subject to the privileges of the user running PeerCast." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/427160/30/0/threaded" );
 # http://web.archive.org/web/20070713004957/http://www.peercast.org/forum/viewtopic.php?t=3346
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ed1ade41" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PeerCast version 0.1217 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'PeerCast URL Handling Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/09");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_dependencies("peercast_installed.nasl");
  script_require_keys("PeerCast/installed");
  script_require_ports("Services/www", 7144);

  exit(0);
}


if (!get_kb_item("PeerCast/installed")) exit(0);

include("global_settings.inc");

list = get_kb_list("PeerCast/*/version");
if (isnull(list)) exit(0);

foreach key (keys(list))
{
  port = key - "PeerCast/" - "/version";
  ver = list[key];

  if (get_port_state(port))
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
}
