#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(44077);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_cve_id("CVE-2006-4925", "CVE-2006-5794", "CVE-2007-0726");
  script_bugtraq_id(20956);
  script_osvdb_id(29494, 30232, 34850);

  script_name(english:"OpenSSH < 4.5 Multiple Vulnerabilities");
  script_summary(english:"Checks for remote SSH version");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
OpenSSH prior to 4.5.  Versions before 4.5 are affected by the
following vulnerabilities :

  - A client-side NULL pointer dereference, caused by a
    protocol error from a malicious server, which could
    cause the client to crash. (CVE-2006-4925)

  - A privilege separation vulnerability exists, which could 
    allow attackers to bypass authentication. The 
    vulnerability is caused by a design error between 
    privileged processes and their child processes. Note 
    that this particular issue is only exploitable when 
    other vulnerabilities are present. (CVE-2006-5794)

  - An attacker that connects to the service before it has 
    finished creating keys could force the keys to be 
    recreated. This could result in a denial of service for 
    any processes that relies on a trust relationship with 
    the server. Note that this particular issue only affects 
    the Apple implementation of OpenSSH on Mac OS X. 
    (CVE-2007-0726)"
  );

  script_set_attribute(attribute:"see_also", value:"http://www.openssh.org/txt/release-4.5");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/TA24626");
  script_set_attribute(attribute:"see_also", value:"http://openssh.com/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH 4.5 or later.
For Mac OS X 10.3, apply Security Update 2007-003.
For Mac OS X 10.4, upgrade to 10.4.9.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/04");
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
if (isnull(matches))  exit(0, 'Could not parse number from version string on port ' + port + '.');

version = matches[1];
if (version =~ '^([0-3]\\..*|4\\.[0-4]($|[^\\.0-9]|\\..*))')
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 4.5\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'The OpenSSH server on port '+port+' is not affected as it\'s version '+version+'.');
