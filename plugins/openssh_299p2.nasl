#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(44070);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2011/10/04 17:26:57 $");

  script_cve_id("CVE-2001-1382");
  script_osvdb_id(5408);

  script_name(english:"OpenSSH < 2.9.9p2 echo simulation Information Disclosure");
  script_summary(english:"Checks for remote SSH version");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is affected by an information disclosure
vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
OpenSSH earlier than 2.9.9p2.  It therefore can potentially disclose
the fact that the 'echo simulation' countermeasure is in use because
the application sends an additional echo packet after the password and
carriage return is entered. 

Note that this issue only exists when the 'echo simulation'
countermeasure is enabled.");

  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 2.9.9p2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2001/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:'ssh', exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit('SSH/banner/'+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ('openssh' >!< bp_banner) exit(0, 'The SSH service on port '+port+' is not OpenSSH.');
if (backported) exit(1, 'The banner from the OpenSSH server on port '+port+' indicates patches may have been backported.');

# Check the version in the banner.
matches = eregmatch(string:bp_banner, pattern:'openssh[-_]([0-9][-._0-9a-z]+)');
if (isnull(matches)) exit(0, 'Could not parse number from version string on port ' + port + '.');

version = matches[1];

if (version =~ '^([0-1]\\..*|2\\.([0-8]\\..*|9\\.([0-8]([^0-9]|$)|9($|[^0-9p]|p[01]([^0-9]|$)))))')
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 2.9.9p2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, 'The OpenSSH server on port '+port+' is not affected as it\'s version '+version+'.');
