#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(44067);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2012/10/23 15:06:52 $");

  script_cve_id("CVE-2000-0217");
  script_bugtraq_id(1006);
  script_osvdb_id(1229);

  script_name(english:"OpenSSH < 1.2.3 xauth Session Highjacking");
  script_summary(english:"Checks for remote SSH version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
session highjacking vulnerability.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
OpenSSH earlier than 1.2.3.  Such versions are affected by a session
highjacking vulnerability.  By default, ssh clients negotiate to
forward X connections by using the xauth program to place cookies in
the authorization cache of the remote machine for the user that is
logging in.  It is possible for the xauth key to be read from the
user's .Xauthority file which could allow a remote attacker to control
the client's X sessions via a malicious xauth program.");

  script_set_attribute(attribute:"see_also", value:"http://www.openssh.org/txt/release-1.2.3p1");
  script_set_attribute(attribute:"see_also", value:"http://openssh.com/security.html");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=95151911210810&w=4");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSH 1.2.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2000/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:'ssh', exit_on_fail:TRUE);

banner = get_kb_item_or_exit('SSH/banner/'+port);

bp_banner = tolower(get_backport_banner(banner:banner));
if ('openssh' >!< bp_banner) exit(0, 'The SSH service on port '+port+' is not OpenSSH.');
if (backported) exit(1, 'The banner from the OpenSSH server on port '+port+' indicates patches may have been backported.');

# Check the version in the banner.
matches = eregmatch(string:bp_banner, pattern:'openssh[-_]([0-9][-._0-9a-z]+)');
if (isnull(matches)) exit(0, 'Could not parse number from version string on port ' + port + '.');
version = matches[1];

if (version =~ '^(0\\.|1\\.([01](\\.|[^\\.0-9]|$)|2([^\\.0-9]|$|\\.[0-2]([^0-9]|$))))')
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 1.2.3\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, 'The OpenSSH server on port '+port+' is not affected as it\'s version '+version+'.');
