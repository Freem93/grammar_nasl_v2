#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17700);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/02 14:37:07 $");

  script_cve_id("CVE-2000-0535");
  script_bugtraq_id(1340);
  script_osvdb_id(3938);

  script_name(english:"OpenSSH < 2.1.0 /dev/random Check Failure");
  script_summary(english:"Checks the version of OpenSSH");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of SSH that may have weak
encryption keys.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSH running on the remote
host is less than 2.1.0. On a FreeBSD system running on the Alpha
architecture, versions earlier than that may not use the /dev/random
and /dev/urandom devices to provide a strong source of cryptographic
entropy, which could lead to the generation of keys with weak
cryptographic strength.");
  script_set_attribute(attribute:"see_also", value:"http://cvs.openssl.org/fileview?f=openssl/CHANGES&v=1.514");
  # https://web.archive.org/web/20000819114726/http://archives.neohapsis.com/archives/freebsd/2000-06/0083.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16bc8320");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?947aedf5");
  script_set_attribute(attribute:"solution", value:
"Upgrade OpenSSH to version 2.1.0 or higher / OpenSSL to version 0.9.5a
or higher and re-generate encryption keys.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ssh");

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

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

match = eregmatch(string:version, pattern:"^([0-9.]+)");
if (isnull(match)) exit(1, 'Failed to parse the version (' + version + ') of the service listening on port '+port+'.');

fix = "2.1.0";
if (ver_compare(ver:match[1], fix:fix, strict:FALSE) == -1)
{
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
}
else exit(0, "The OpenSSH version "+version+" server listening on port "+port+" is not affected.");
