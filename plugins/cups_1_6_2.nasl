#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65970);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2012-5519");
  script_bugtraq_id(56494);
  script_osvdb_id(87635, 92072, 92073, 92074, 92075, 92076);

  script_name(english:"CUPS < 1.6.2 Multiple Vulnerabilities");
  script_summary(english:"Checks CUPS server version");

  script_set_attribute(attribute:"synopsis", value:
"The remote print service is potentially affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is earlier than 1.6.2. It is, therefore, potentially affected by
the following vulnerabilities :

  - Permissions on the file '/var/run/cups/certs/0' could
    allow access to CUPS administration interface
    authentication key material and thus, the interface
    itself with admin rights. Additionally, users with admin
    rights can edit the configuration file and specify
    malicious commands that are then carried out with root
    user permissions. (CVE-2012-5519)

  - Multiple errors exist related to the functions
    'ippEnumString', 'ippReadIO', 'set_time',
    'load_request_root' and 'http_resolve_cb' that could
    allow denial of service attacks.");
  script_set_attribute(attribute:"see_also", value:"https://www.cups.org/blog/2013-03-18-cups-1.6.2.html");
  script_set_attribute(attribute:"see_also", value:"https://github.com/apple/cups/issues/4223");
  script_set_attribute(attribute:"see_also", value:"https://github.com/apple/cups/issues/4242");
  script_set_attribute(attribute:"see_also", value:"http://www.openwall.com/lists/oss-security/2012/11/11/2");
  script_set_attribute(attribute:"see_also", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=692791");
  script_set_attribute(attribute:"solution", value:"Upgrade to CUPS version 1.6.2 or later, or apply the vendor patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^(1|1\.6)($|[^0-9rb.])") audit(AUDIT_VER_NOT_GRANULAR, "CUPS", port, version);

if (
  version =~ "^1\.[0-5]($|[^0-9])" ||
  version =~ "^1\.6\.[01]($|[^0-9.])" ||
  version =~ "^1\.6(rc|b)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.6.2\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "CUPS", port, version);
