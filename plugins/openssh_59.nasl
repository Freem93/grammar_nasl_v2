#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17703);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/07/23 10:39:54 $");

  script_cve_id("CVE-2010-4755","CVE-2011-5000");
  script_bugtraq_id(54114, 68757);
  script_osvdb_id(75248, 75249, 81500);

  script_name(english:"OpenSSH < 5.9 Multiple DoS");
  script_summary(english:"Checks OpenSSH banner version");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server on the remote host has multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is prior to version 5.9. Such versions are affected by multiple
denial of service vulnerabilities :

  - A denial of service vulnerability exists in the
    gss-serv.c 'ssh_gssapi_parse_ename' function.  A remote
    attacker may be able to trigger this vulnerability if
    gssapi-with-mic is enabled to create a denial of service
    condition via a large value in a certain length field.
    (CVE-2011-5000)

  - On FreeBSD, NetBSD, OpenBSD, and other products, a
    remote, authenticated attacker could exploit the
    remote_glob() and process_put() functions to cause a
    denial of service (CPU and memory consumption).
    (CVE-2010-4755)");
  script_set_attribute(attribute:"see_also", value:"http://cxsecurity.com/research/89");
  script_set_attribute(attribute:"see_also",value:"http://site.pi3.com.pl/adv/ssh_1.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 5.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/PCI_DSS");
  script_require_ports("Services/ssh");

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# OpenSSH is only affected on certain OSes.
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");


# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) exit(1, "Could not parse the version string in the banner from port "+port+".");
version = match[1];


if (
  version =~ "^[0-4]\." ||
  version =~ "^5\.[0-8]($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.9\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The OpenSSH version "+version+" server listening on port "+port+" is not affected.");
