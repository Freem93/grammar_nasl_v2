#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53841);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2011-4327");
  script_bugtraq_id(47691);
  script_osvdb_id(72183);
  script_xref(name:"Secunia", value:"44347");

  script_name(english:"Portable OpenSSH ssh-keysign ssh-rand-helper Utility File Descriptor Leak Local Information Disclosure");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(attribute:"synopsis", value:"Local attackers may be able to access sensitive information.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of OpenSSH running on the remote
host is earlier than 5.8p2.  Such versions may be affected by a local
information disclosure vulnerability that could allow the contents of
the host's private key to be accessible by locally tracing the
execution of the ssh-keysign utility.  Having the host's private key
may allow the impersonation of the host. 

Note that installations are only vulnerable if ssh-rand-helper was
enabled during the build process, which is not the case for *BSD, OS
X, Cygwin and Linux."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Portable OpenSSH 5.8p2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/portable-keysign-rand-helper.adv");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-5.8p2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/09");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh");

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/"+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ("openssh" >!< bp_banner) exit(0, "The SSH service on port "+port+" is not OpenSSH.");
if (backported) exit(1, "The banner from the OpenSSH server on port "+port+" indicates patches may have been backported.");

# Check the version in the banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match))
  exit(1, "Could not parse the version string from the banner on port " + port + ".");
version = match[1];

# Check whether the version is vulnerable.
matches = eregmatch(string:version, pattern:"([0-9.]+)(?:p([0-9]+))?");
if (isnull(matches))
  exit(0, "Could not parse number from version string on port " + port + ".");

ver = make_list();
foreach field (split(matches[1], sep:"."))
  ver = make_list(ver, int(field));

if (
  (ver[0] < 5) ||
  (ver[0] == 5 && ver[1] < 8) ||
  (ver[0] == 5 && ver[1] == 8 && isnull(matches[2])) ||
  (ver[0] == 5 && ver[1] == 8 && !isnull(matches[2]) && int(matches[2]) < 2)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.8p2\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, "The Portable OpenSSH server on port "+port+" is not affected as it's version "+version+".");
