#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45435);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2010-0009");
  script_bugtraq_id(39116);
  script_osvdb_id(63350);
  script_xref(name:"Secunia", value:"39146");

  script_name(english:"Apache CouchDB < 0.11.0 Hash Verification Information Leak");
  script_summary(english:"Does a paranoid banner check on the web server");

  script_set_attribute(attribute:"synopsis", value:"The remote database server has an information leak vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CouchDB running on the remote
host has an information leak vulnerability. The application does not
use a constant-time comparison algorithm when attempting to verify
hashes and passwords. The server will respond to mismatches more
quickly than it responds to matches.

A remote attacker could exploit this by performing side-channel brute
force attacks, which could lead to administrative access.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Mar/254");
  script_set_attribute(attribute:"solution", value:"Upgrade to CouchDB 0.11.0 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("couchdb_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "www/couchdb");
  script_require_ports("Services/www", 5984);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port    = get_http_port(default:5984);
install = get_install_from_kb(appname:"couchdb", port:port, exit_on_fail:TRUE);

version = install['ver'];
if (version == UNKNOWN_VER) exit(1, "An unknown version of CouchDB is listening on port "+port+".");

ver_fields = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver_fields); i++)
  ver_fields[i] = int(ver_fields[i]);

if (
  ver_fields[0] == 0 &&
  (
    ver_fields[1] == 8 ||
    ver_fields[1] == 9 ||
    (ver_fields[1] == 10 && ver_fields[2] <= 1)
  )
)
{
  if (report_verbosity > 0)
  {
    source  = get_kb_item("www/"+port+"/couchdb/source");
    if (!source) source = "n/a";

    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 0.11.0\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, 'CouchDB version '+version+' on port '+port+' is not affected.');
