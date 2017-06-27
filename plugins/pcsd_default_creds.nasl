#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83266);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_cve_id("CVE-2015-1842");
  script_bugtraq_id(74049);
  script_osvdb_id(120287);

  script_name(english:"ClusterLabs Pacemaker PCS Daemon Default Password");
  script_summary(english:"Attempts to login using the default password.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a service with known default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote ClusterLabs Pacemaker PCS daemon uses a known default set
of credentials. This allows a remote attacker to run arbitrary
commands on cluster members.

Note that some package deployment systems, such as Puppet, may be
responsible for setting these default credentials.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1201875");
  script_set_attribute(attribute:"solution", value:
"Change the password on known default accounts.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/03/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/07");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:clusterlabs:pacemaker");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("pcsd_detect.nbin");
  script_require_ports("Services/www", 2224);
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/PCSD");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:2224);
app = "PCSD";

install = get_install_from_kb(
  appname      : app,
  port         : port,
  exit_on_fail : TRUE
);

url = '/remote/auth';
user = "hacluster";
pass = "CHANGEME";

postdata = "username=" + user + "&password=" + pass + "&bidirectional=1";

res = http_send_recv3(
  method : "POST",
  item   : url,
  port   : port,
  data   : postdata,
  add_headers : make_array("Content-Type", "application/x-www-form-urlencoded"),
  exit_on_fail : TRUE
);

res = http_send_recv3(
  method : "GET",
  item   : "/remote/status", 
  add_headers : make_array("Cookie", "token=" + res[2]),
  port   : port,
  exit_on_fail : TRUE
);

if('{"notauthorized":"true"}' >!< res[2] &&
   '"pacemaker":' >< res[2] && '"cluster_settings":' >< res[2])
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to gain access using the following URL';
    trailer =
      'and the following set of credentials :\n' +
      '\n' +
      '  Username : ' + user + '\n' +
      '  Password : ' + pass;

    report = get_vuln_report(
      items   : url,
      port    : port,
      header  : header,
      trailer : trailer
    );

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(port:port, qs:"/"));
