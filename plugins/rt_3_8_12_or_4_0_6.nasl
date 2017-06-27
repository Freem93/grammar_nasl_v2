#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61434);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id(
    "CVE-2011-2082",
    "CVE-2011-2083",
    "CVE-2011-2084",
    "CVE-2011-2085",
    "CVE-2011-4458",
    "CVE-2011-4459",
    "CVE-2011-4460",
    "CVE-2011-5092",
    "CVE-2011-5093"
  );
  script_bugtraq_id(53660);
  script_osvdb_id(
    82129,
    82130,
    82133,
    82134,
    82135,
    82136,
    82140,
    82729,
    82758
  );

  script_name(english:"Request Tracker 3.x < 3.8.12 / 4.x < 4.0.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Request Tracker.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a Perl application that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Best Practical
Solutions Request Tracker (RT) running on the remote web server is
version 3.x prior to 3.8.12 or version 4.x prior to 4.0.6. It is,
therefore, potentially affected by the following vulnerabilities :

  - The 'vulnerable-passwords' script fails to update the
    password-hash of disabled users, which could enable an
    attacker to more easily determine plaintext passwords
    using brute force methods. (CVE-2011-2082)

  - Multiple cross-site scripting vulnerabilities exist that
    an attacker can utilize to execute script code with the
    user's credentials. (CVE-2011-2083)

  - A remote, authenticated attacker can read the hashes of
    former passwords and the ticket correspondence history
    by accessing a privileged account. (CVE-2011-2084)

  - Multiple cross-site request forgery vulnerabilities
    exist which a remote attacker can exploit to hijack user
    authentication. (CVE-2011-2085)

  - A remote code execution vulnerability exists if the
    optional VERP configuration options (VERPPrefix and
    VERPDomain) are enabled. (CVE-2011-4458)

  - Groups are not properly disabled, allowing users in
    disabled groups to gain escalated privileges.
    (CVE-2011-4459)

  - A remote, authenticated attacker can inject SQL commands
    by utilizing access to a privileged account, allowing
    the disclosure or manipulation of arbitrary data on the
    back-end database. (CVE-2011-4460)

  - An unspecified vulnerability exists that allows remote
    attackers to gain privileges or execute a restricted
    amount of arbitrary code. (CVE-2011-5092)

  - The DisallowExecuteCode option is not properly
    implemented and allows a remote, authenticated attacker
    to bypass intended access restrictions and execute
    arbitrary code by using access to a privileged account.
    (CVE-2011-5093)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  #http://blog.bestpractical.com/2012/05/security-vulnerabilities-in-rt.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebd34bfd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Request Tracker 3.8.12 / 4.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bestpractical:rt");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("rt_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/RT", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'RT';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

path = install["path"];
version = install["version"];
install_loc = build_url(port:port, qs:path + "/");

ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

# Versions less than 3.8.12 / 4.0.6 are affected.
if (
  ver[0] < 3 ||
  (
    ver[0] == 3 &&
    (
      ver[1] < 8 || 
      (ver[1] == 8 && ver[2] < 12) ||
      (ver[1] == 8 && ver[2] == 12 && version =~ "(rc|pre|alpha|RC|test|CH|beta|preflight)")
    )
  ) ||
  (
    ver[0] == 4 && ver[1] == 0 &&
    (
      (ver[2] < 6) ||
      (ver[2] == 6 && version =~ "(rc|pre|alpha|RC|test|CH|beta|preflight)")
    )
  )
)  
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
  set_kb_item(name:"www/"+port+"/SQLInjection", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_loc+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.8.12 / 4.0.6\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
