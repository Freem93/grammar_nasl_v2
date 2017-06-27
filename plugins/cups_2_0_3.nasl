#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84149);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/15 14:00:39 $");

  script_cve_id("CVE-2015-1158", "CVE-2015-1159");
  script_bugtraq_id(75098);
  script_xref(name:"CERT", value:"810572");

  script_name(english:"CUPS < 2.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the CUPS server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote printer service is potentially affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the CUPS printer service running on the
remote host is a version prior to 2.0.3. It is, therefore, potentially
affected by the following vulnerabilities :

  - A privilege escalation vulnerability exists due to a
    flaw in cupsd when handling printer job request errors.
    An unauthenticated, remote attacker can exploit this,
    with a specially crafted request, to prematurely free an
    arbitrary string of global scope, creating a dangling
    pointer to a repurposed block of memory on the heap, 
    resulting ACL verification to fail when parsing
    'admin/conf' and 'admin' ACLs. This allows an attacker
    to upload a replacement CUPS configuration file.
    (CVE-2015-1158)

  - A cross-site scripting vulnerability exists due to
    improper sanitization of user-supplied input to the
    'QUERY' parameter of the help page. This allows a remote
    attacker, with a specially crafted request, to execute
    arbitrary script code. (CVE-2015-1159)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # Blog
  script_set_attribute(attribute:"see_also", value:"https://cups.org/blog.php?L1082");
  # Bug
  script_set_attribute(attribute:"see_also", value:"https://cups.org/str.php?L4609");
  script_set_attribute(attribute:"solution", value:
"Upgrade to CUPS version 2.0.3 or later. Alternatively, apply the patch
provided by the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cups_1_3_5.nasl");
  script_require_keys("www/cups", "Settings/ParanoidReport");
  script_require_ports("Services/www", 631);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:631, embedded:TRUE);
get_kb_item_or_exit("www/"+port+"/cups/running");

version = get_kb_item_or_exit("cups/"+port+"/version");
source  = get_kb_item_or_exit("cups/"+port+"/source");

if (version =~ "^(2|2\.0)($|[^0-9br.])") audit(AUDIT_VER_NOT_GRANULAR, "CUPS", port, version);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Affected :
# x.x.x < 2.0.3
if (
  version =~ "^1\." ||
  version =~ "^2\.0\.[0-2]($|[^0-9.])" ||
  version =~ "^2\.0(rc|b)"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.0.3' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "CUPS", port, version);
