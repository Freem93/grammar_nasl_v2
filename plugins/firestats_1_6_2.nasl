#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39621);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id("CVE-2009-2143", "CVE-2009-2144");
  script_bugtraq_id(35367, 35533);
  script_osvdb_id(55087, 55088);
  script_xref(name:"EDB-ID", value:"8945");
  script_xref(name:"Secunia", value:"35400");

  script_name(english:"FireStats < 1.6.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of FireStats.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the install of FireStats running on
the remote host is affected by multiple vulnerabilities :

  - A remote file include vulnerability in the
    'fs_javascript' parameter of 'firestats-wordpress.php'.
    (CVE-2009-2143)

  - An unspecified SQL injection vulnerability.
    (CVE-2009-2144)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://firestats.cc/wiki/ChangeLog#a1.6.2-stable13062009");

  script_set_attribute(attribute:"solution", value:"Upgrade to FireStats 1.6.2-stable or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89, 94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:edgewall:firestats");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("firestats_detect.nasl", "wordpress_detect.nasl");
  script_require_keys("installed_sw/FireStats", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "FireStats";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(port:port, qs:dir);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affects versions < 1.6.2
if (
  (ver[0] < 1) ||
  (ver[0] == 1 && ver[1] < 6) ||
  (ver[0] == 1 && ver[1] == 6 && ver[2] < 2)
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 1.6.2-stable\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
