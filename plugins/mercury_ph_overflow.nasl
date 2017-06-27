#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20812);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id("CVE-2005-4411");
  script_bugtraq_id(16396);
  script_osvdb_id(22103);
  script_xref(name:"EDB-ID", value:"1375");

  script_name(english:"Mercury Mail ph Server Remote Overflow");
  script_summary(english:"Checks for a buffer overflow vulnerability in Mercury ph Server");

  script_set_attribute(attribute:"synopsis", value:"The remote ph service is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running the Mercury Mail Transport System, a free
suite of server products for Windows and Netware associated with
Pegasus Mail.

The remote installation of Mercury includes a ph server that is
vulnerable to buffer overflow attacks. By leveraging this issue, an
unauthenticated, remote attacker is able to crash the remote service
and possibly execute arbitrary code remotely.");
  script_set_attribute(attribute:"see_also", value:"http://www.pmail.com/newsflash.htm#whfix");
  script_set_attribute(attribute:"see_also", value:"http://www.pmail.com/patches.htm");
  script_set_attribute(attribute:"solution", value:
"Install the Jan 2006 Mercury/32 Security patches for MercuryW and
MercuryH.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mercury/32 PH Server Module Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/ph", 105);

  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/ph");
if (!port) port = 105;
if (!get_tcp_port_state(port)) exit(0);


# Open a connection.
soc = open_sock_tcp(port);
if (soc) {
  # If safe checks are enabled...
  if (safe_checks() || report_paranoia < 2 ) {
    # Try to pull out the version number from the HELP.
    send(socket:soc, data:string("HELP\r\n"));
    res = recv(socket:soc, length:1024);
    if (res == NULL) exit(0);

    # nb: the banner with the patch applied reports "Mercury Simple PH Server v4.1 beta 6".
    if (egrep(pattern:" Mercury Simple PH Server v([0-3]\.|4\.0(0|1($|[ab])))", string:res)) {
      report = string(
        "Nessus has determined the flaw exists with the application\n",
        "simply by looking at the version in its banner.\n"
      );
      security_hole(port:port, extra:report);
    }
  }
  # Otherwise...
  else {
    # Try to crash the service.
    send(socket:soc, data:string(crap(1000), "\r\n"));
    res = recv(socket:soc, length:256);

    # Try to reconnect if we didn't get anything back.
    if (res == NULL) {
      soc2 = open_sock_tcp(port);
      if (soc2) close(soc2);
      else {
        security_hole(port);
        exit(0);
      }
    }
  }

  close(soc);
}
