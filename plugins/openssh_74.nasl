#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96151);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/29 14:22:37 $");

  script_cve_id(
    "CVE-2016-10009",
    "CVE-2016-10010",
    "CVE-2016-10011",
    "CVE-2016-10012"
  );
  script_bugtraq_id(
    94968,
    94972,
    94975,
    94977
  );
  script_osvdb_id(
    148966,
    148967,
    148968,
    148975,
    148976,
    148977
  );
  script_xref(name:"EDB-ID", value:"40962");

  script_name(english:"OpenSSH < 7.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the OpenSSH banner version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to 7.4. It is, therefore, affected by multiple
vulnerabilities :

  - A flaw exists in ssh-agent due to loading PKCS#11
    modules from paths that are outside a trusted whitelist.
    A local attacker can exploit this, by using a crafted
    request to load hostile modules via agent forwarding, to
    execute arbitrary code. To exploit this vulnerability,
    the attacker would need to control the forwarded
    agent-socket (on the host running the sshd server) and
    the ability to write to the file system of the host
    running ssh-agent. (CVE-2016-10009)

  - A flaw exists in sshd due to creating forwarded
    Unix-domain sockets with 'root' privileges whenever
    privilege separation is disabled. A local attacker can
    exploit this to gain elevated privileges.
    (CVE-2016-10010)

  - An information disclosure vulnerability exists in sshd
    within the realloc() function due leakage of key
    material to privilege-separated child processes when
    reading keys. A local attacker can possibly exploit this
    to disclose sensitive key material. Note that no such
    leak has been observed in practice for normal-sized
    keys, nor does a leak to the child processes directly
    expose key material to unprivileged users.
    (CVE-2016-10011)

  - A flaw exists in sshd within the shared memory manager
    used by pre-authenticating compression support due to a
    bounds check being elided by some optimizing compilers
    and due to the memory manager being incorrectly
    accessible when pre-authenticating compression is
    disabled. A local attacker can exploit this to gain
    elevated privileges. (CVE-2016-10012)

  - A denial of service vulnerability exists in sshd when
    handling KEXINIT messages. An unauthenticated, remote
    attacker can exploit this, by sending multiple KEXINIT
    messages, to consume up to 128MB per connection.
    (VulnDB 148976)

  - A flaw exists in sshd due to improper validation of
    address ranges by the AllowUser and DenyUsers
    directives at configuration load time. A local attacker
    can exploit this, via an invalid CIDR address range, to
    gain access to restricted areas. (VulnDB 148977)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-7.4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 7.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ssh");

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/" + port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner)
  audit(AUDIT_NOT_LISTEN, "OpenSSH", port);
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);
if (backported)
  audit(code:0, AUDIT_BACKPORT_SERVICE, port, "OpenSSH");

# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match))
  audit(AUDIT_SERVICE_VER_FAIL, "OpenSSH", port);
version = match[1];

fix = "7.4";
if (
  version =~ "^[0-6]\." ||
  version =~ "^7\.[0-3]"
   )
{
  items = make_array("Version source", banner,
                     "Installed version", version,
                     "Fixed version", fix);
  order = make_list("Version source", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);

}
else audit(AUDIT_LISTEN_NOT_VULN, "OpenSSH", port, version);
