#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44068);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2001-0361", "CVE-2001-0572");
  script_bugtraq_id(2344, 49473);
  script_osvdb_id(2116, 3562);
  script_xref(name:"CERT", value:"596827");

  script_name(english:"OpenSSH < 2.5.2 / 2.5.2p2 Multiple Information Disclosure Vulnerabilities");
  script_summary(english:"Checks the version reported in the SSH banner.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Remote attackers may be able to infer information about traffic
inside an SSH session."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the remote host appears to be running a
version of OpenSSH earlier than 2.5.2 / 2.5.2p2. It, therefore,
reportedly contains weaknesses in its implementation of the SSH
protocol, both versions 1 and 2.  These weaknesses could allow an
attacker to sniff password lengths, and ranges of length (this could
make brute-force password guessing easier), determine whether RSA or
DSA authentication is being used, the number of authorized_keys in RSA
authentication and/or the length of shell commands."
  );

  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to OpenSSH 2.5.2 / 2.5.2p2 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/articles/SSH-Traffic-Analysis");
  script_set_attribute(attribute:"see_also", value:"http://www.openssh.com/txt/release-2.5.2p2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
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

# Check the version in the backported banner.
match = eregmatch(string:bp_banner, pattern:"openssh[-_]([0-9][-._0-9a-z]+)");
if (isnull(match)) exit(1, "Could not parse the version string in the banner from port "+port+".");
version = match[1];

if (version !~ "^[0-9.]+p[0-9]+")
{
  # Pull out numeric portion of version of the native OpenBSD version.
  matches = eregmatch(string:version, pattern:"^([0-9.]+)");
  if (isnull(matches)) # this should never happen due to the previous eregmatch() call, but let's code defensively anyway
    exit(1, 'Failed to parse the version (' + version + ') of the service listening on port '+port+'.');

  fix = "2.5.2";
  if (ver_compare(ver:matches[1], fix:fix, strict:FALSE) >= 0)
    exit(0, "The OpenSSH server on port "+port+" is not affected as it's version "+version+".");
}
else
{
  # Pull out numeric portion of version of the portable version.
  matches = eregmatch(string:version, pattern:"^([0-9.]+)p([0-9]+)");
  if (isnull(matches)) # this should never happen due to the previous eregmatch() call, but let's code defensively anyway
    exit(1, 'Failed to parse the version (' + version + ') of the service listening on port '+port+'.');

  fix = "2.5.2p2";
  if (
    (ver_compare(ver:matches[1], fix:"2.5.2", strict:FALSE) > 0) ||
    (matches[1] == "2.5.2" && int(matches[2]) >= 2)
  ) exit(0, "The OpenSSH server on port "+port+" is not affected as it's version "+version+".");
}

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
