#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(18200);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-1478", "CVE-2005-1516");
  script_bugtraq_id(13497, 13505);
  script_osvdb_id(16299, 16300);
  script_xref(name:"Secunia", value:"15242");

  script_name(english:"NetWin DMail Server Multiple Remote Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is susceptible to multiple issues." );
 script_set_attribute(attribute:"description", value:
"The installation of NetWin DMail on the remote host suffers from an
authentication bypass vulnerability in its mailing list server
component, DList, and a format string vulnerability in the SMTP server
component, DSmtp.  An attacker can exploit the first to reveal
potentially sensitive log information as well as to shut down the
DList process and, provided he has the admin password, the second to
crash the DSmtp process and potentially execute arbitrary code on the
remote." );
 script_set_attribute(attribute:"solution", value:
"Block access to the affected port with a firewall." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/03");
 script_cvs_date("$Date: 2016/12/06 20:34:49 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for two vulnerabilities in NetWin DMail");
  script_category(ACT_ATTACK);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/DMAIL_Admin", 7111);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item("Services/DMAIL_Admin");
if (!port) port = 7111;
if (!get_port_state(port)) exit(0);


# Connect to the port.
soc = open_sock_tcp(port);
if (!soc) exit(0);
res = recv_line(socket:soc, length:4096);


# If it looks like DMail's DMAdmin...
if (res && res =~ "^hash [0-9]+") {
  # Try to exploit the vulnerability by grabbing the logs.
  send(socket:soc, data:string("sendlog 234343\n"));
  res = recv_line(socket:soc, length:4096);

  # There's a problem if Dlist claims to be sending them.
  if (res && res =~ "^ok Dlist .+ sending log") security_warning(port);
}
close(soc);
