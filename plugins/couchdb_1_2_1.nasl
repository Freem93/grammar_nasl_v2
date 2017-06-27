#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63642);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/02 19:32:50 $");

  script_cve_id("CVE-2012-5641", "CVE-2012-5649", "CVE-2012-5650");
  script_bugtraq_id(57313, 57314, 57321);
  script_osvdb_id(89267, 89293, 89294);

  script_name(english:"Apache CouchDB < 1.0.4 / 1.1.2 / 1.2.1 Multiple Vulnerabilities");
  script_summary(english:"Does a paranoid banner check on the web server");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is potentially affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CouchDB running on the remote
host is earlier than 1.0.4, 1.1.x earlier than 1.1.2 or 1.2.x earlier
than 1.2.1.  It is, therefore, potentially affected by the following
vulnerabilities :

  - An unspecified error exists in the included MochiWeb
    HTTP library that can allow access to arbitrary files
    via directory traversal attacks. Note that reportedly,
    this issue only affects installs on Windows hosts.
    (CVE-2012-5641)

  - An error related to JSONP callbacks can allow an
    unspecified cross-site scripting attack. (CVE-2012-5649)

  - An input validation error exists related to unspecified
    query parameters and the Futon UI that can allow DOM-
    based cross-site scripting attacks. (CVE-2012-5650)

Note that Nessus did not actually test for these flaws but instead, has
relied on the version in CouchDB's banner.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525297/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525299/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525300/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to CouchDB 1.0.4 / 1.1.2 / 1.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:couchdb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("couchdb_detect.nasl");
  script_require_ports("Services/www", 5984, 6984);
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

if (version =~ "^1(\.[0-2])?$") exit(1, "The banner from the CouchDB install listening on port "+port+" - "+version+" -  is not granular enough to make a determination.");

ver_fields = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver_fields); i++)
  ver_fields[i] = int(ver_fields[i]);

if (
  ver_fields[0] == 0 ||
  (
    ver_fields[0] == 1 &&
    (
      (ver_fields[1] == 0 && ver_fields[2] < 4) ||
      (ver_fields[1] == 1 && ver_fields[2] < 2) ||
      (ver_fields[1] == 2 && ver_fields[2] < 1)
    )
  )
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
      '\n  Fixed version     : 1.0.4 / 1.1.2 / 1.2.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "CouchDB", port, version);
