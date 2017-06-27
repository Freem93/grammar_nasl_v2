#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(17705);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/02 14:37:07 $");

  script_cve_id("CVE-2007-2768");
  script_osvdb_id(34601);

  script_name(english:"OPIE w/ OpenSSH Account Enumeration");
  script_summary(english:"Checks if OpenSSH is installed");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is susceptible to an information disclosure attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"When using OPIE for PAM and OpenSSH, it is possible for remote
attackers to determine the existence of certain user accounts. 

Note that Nessus has not tried to exploit the issue, but rather only
checked if OpenSSH is running on the remote host.  As a result, it
does not detect if the remote host actually has OPIE for PAM
installed."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Apr/634");
  script_set_attribute(
    attribute:"solution",
    value:
"A patch currently does not exist for this issue. As a workaround,
ensure that OPIE for PAM is not installed."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

# Ensure the port is open.
port = get_service(svc:'ssh', exit_on_fail:TRUE);

# Get banner for service
banner = get_kb_item_or_exit("SSH/banner/"+port);

if ("openssh" >!< tolower(banner)) exit(0, "The SSH service on port "+port+" is not OpenSSH.");

match = eregmatch(string:tolower(banner), pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) exit(1, "Could not parse the version string in the banner from port "+port+".");
version = match[1];

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + version +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
