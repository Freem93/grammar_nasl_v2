#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51923);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/02 19:32:50 $");

  script_cve_id("CVE-2010-3854");
  script_bugtraq_id(46066);
  script_osvdb_id(70734);
  script_xref(name:"Secunia", value:"43111");

  script_name(english:"Apache CouchDB < 1.0.2 Futon Admin Interface XSS");
  script_summary(english:"Does a paranoid banner check on the web server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CouchDB running on the remote
host is affected by a cross-site scripting vulnerability.  The
application fails to properly sanitize user-supplied input before it
is used in the Futon admin interface. 

A remote attacker could exploit this to execute arbitrary script code
in the security context of CouchDB's admin interface.

Note that Nessus did not actually test for the flaw but instead has
relied on the version in CouchDB's banner so this may be a false
positive.");
  # http://mail-archives.apache.org/mod_mbox/couchdb-dev/201101.mbox/%3CC840F655-C8C5-4EC6-8AA8-DD223E39C34A@apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a644bca1");
  script_set_attribute(attribute:"solution", value:"Upgrade to CouchDB 1.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/09");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:couchdb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("couchdb_detect.nasl");
  script_require_ports("Services/www", 5984);
  script_require_keys("Settings/ParanoidReport", "www/couchdb");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port    = get_http_port(default:5984);
install = get_install_from_kb(appname:"couchdb", port:port, exit_on_fail:TRUE);

version = install['ver'];
if (version == UNKNOWN_VER) audit(AUDIT_SERVICE_VER_FAIL, "CouchDB", port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver_fields = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver_fields); i++)
  ver_fields[i] = int(ver_fields[i]);

if (
  (ver_fields[0] == 0 && ver_fields[1] >= 8) || 
  (ver_fields[0] == 1 && ver_compare(ver:version, fix:"1.0.2", strict:FALSE) < 0)
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    source  = get_kb_item("www/"+port+"/couchdb/source");
    if (!source) source = "n/a";

    report = 
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.0.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "CouchDB", port, version);
