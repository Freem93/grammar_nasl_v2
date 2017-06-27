#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45434);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/21 20:34:20 $");

  script_name(english:"Apache CouchDB Unauthenticated Administrative Access");
  script_summary(english:"Tries to get the CouchDB config");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote database server allows administrative access without
authentication."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to perform administrative actions on the remote
CouchDB server without providing authentication.  A remote attacker
could exploit this to take control of the CouchDB server."
  );
  script_set_attribute(attribute:"see_also", value:"http://books.couchdb.org/relax/reference/security");
  script_set_attribute(attribute:"solution", value:"Secure the CouchDB installation with an administrative account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencie("couchdb_detect.nasl");
  script_require_ports("Services/www", 5984);
  script_require_keys("www/couchdb");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:5984);
install = get_install_from_kb(appname:"couchdb", port:port, exit_on_fail:TRUE);

# try to read the active CouchDB configuration
url = install['dir'] + '/_config';
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  'couch_httpd_db' >< res[2] && 'bind_address' >< res[2] &&
  'unauthorized' >!< res[2] && 'You are not a server admin.' >!< res[2]
)
{
  if (report_verbosity > 0)
  {
    trailer = NULL;
    if (report_verbosity > 1)
    {
      trailer =
        'Which returned the following configuration :\n\n'+
        crap(data:"-", length:30)+" snip "+crap(data:"-", length:30)+'\n'+
        res[2]+
        crap(data:"-", length:30)+" snip "+crap(data:"-", length:30);
    }
    report = get_vuln_report(items:url, trailer:trailer, port:port);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, 'The CouchDB server on port '+port+' is not affected.');
