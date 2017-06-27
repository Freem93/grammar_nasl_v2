#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48382);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2010-2234");
  script_bugtraq_id(42501);
  script_osvdb_id(67240);
  script_xref(name:"Secunia", value:"40998");

  script_name(english:"Apache CouchDB < 0.11.2 Futon admin interface Cross-Site Request Forgery");
  script_summary(english:"Does a paranoid banner check on the web server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a cross-site request forgery
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CouchDB running on the remote
host is affected by a cross-site request forgery vulnerability. The
application fails to properly sanitize user-supplied input before it
is used in the Futon admin interface.

A remote attacker could exploit this to execute arbitrary script code
in the security context of CouchDB's admin interface.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Aug/199");
  script_set_attribute(attribute:"solution", value:"Upgrade to CouchDB 0.11.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:couchdb");
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
    ver_fields[1] < 11 ||
    (ver_fieds[1] == 11 && ver_fields[2] < 2)
  )
)
{
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
  if (report_verbosity > 0)
  {
    source  = get_kb_item("www/"+port+"/couchdb/source");
    if (!source) source = "n/a";

    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed Version     : 0.11.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "CouchDB "+version+" is listening on port "+port+" and is not affected.");
