#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17701);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2004-0175");
  script_bugtraq_id(9986);
  script_osvdb_id(9550);

  script_name(english:"OpenSSH < 3.4p1 scp Traversal Arbitrary File Overwrite");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(attribute:"synopsis", value:
"A file transfer client on the remote host could be abused to
overwrite arbitrary files.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is earlier than version 3.4p1.  Such versions contain an
arbitrary file overwrite vulnerability that could allow a malicious
SSH server to cause the supplied scp utility to write to arbitrary
files outside of the current directory.");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 3.4p1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);
  script_set_attribute(attribute:"see_also", value:"http://www.juniper.net/support/security/alerts/adv59739.txt");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=120147");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5cc380af");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_require_ports("Services/ssh");

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Only PCI considers this an issue.
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");

# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) exit(1, "Could not parse the version string in the banner from port "+port+".");
version = match[1];

# Extract the numeric portion of the version number.
match = eregmatch(string:version, pattern:"([0-9.]+)");
if (isnull(match))
  exit(0, "Could not parse number from version string on port " + port + ".");
ver = match[1];

if (ver_compare(ver:ver, fix:"3.4", strict:FALSE) >= 0)
  exit(0, "The OpenSSH version "+version+" server listening on port "+port+" is not affected.");

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 3.4p1' +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
