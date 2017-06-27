#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17744);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2004-1653");
  script_osvdb_id(9562);

  script_name(english:"OpenSSH >= 2.3.0 AllowTcpForwarding Port Bouncing");
  script_summary(english:"Checks for remote SSH version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH server may permit anonymous port bouncing.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running OpenSSH, version
2.3.0 or later.  Such versions of OpenSSH allow forwarding TCP
connections.  If the OpenSSH server is configured to allow anonymous
connections (e.g. AnonCVS), remote, unauthenticated users could use
the host as a proxy.");

  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=109413637313484&w=2");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c86d008");

  script_set_attribute(attribute:"solution", value:
"Disallow anonymous users, set AllowTcpForwarding to 'no', or use the
Match directive to restrict anonymous users.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Only PCI considers this an issue.
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = tolower(get_kb_item_or_exit("SSH/banner/" + port));
if ("openssh" >!< banner) exit(0, "The SSH service on port " + port + " is not OpenSSH.");

# Check the version in the banner.
match = eregmatch(string:banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) exit(1, "Could not parse the version string in the banner from port "+port+".");
version = match[1];

# Extract the numeric portion of the version number.
match = eregmatch(string:version, pattern:"([0-9.]+)");
if (isnull(match)) exit(1, 'Failed to parse the version (' + version + ') of the OpenSSH server listening on port '+port+'.');
ver = match[1];

if (ver_compare(ver:ver, fix:"2.3.0", strict:FALSE) < 0)
  exit(0, "The OpenSSH server on port " + port + " is not affected as it's version " + version + ".");

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + version +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
