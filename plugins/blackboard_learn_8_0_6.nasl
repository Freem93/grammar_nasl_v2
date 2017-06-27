#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74511);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/23 22:03:55 $");

  script_cve_id("CVE-2014-0811");
  script_bugtraq_id(65742);
  script_osvdb_id(103792);

  script_name(english:"Blackboard Learning System <= 8.0 SP6 Unspecified XSS");
  script_summary(english:"Checks the version of Blackboard Learn");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Blackboard Learning System, now
known as Blackboard Learn, install hosted on the remote web server is
affected by an unspecified cross-site scripting vulnerability.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://jvn.jp/en/jp/JVN24730765/index.html");
  script_set_attribute(attribute:"solution", value:"Refer to the vendor for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:blackboard:vista%2fce");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("blackboard_learn_detect.nbin");
  script_require_keys("www/Blackboard Learn");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
app  = 'Blackboard Learn';

install = get_install_from_kb(appname:app, port:port, exit_on_fail:TRUE);
license = get_kb_item("www/" + port + "/" + app + "/license");

version = install["ver"];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, app, install_loc);

dir = install["dir"];
install_loc = build_url(port:port, qs:dir + "/");

# Check license; if paranoid reporting is enabled assume license is affected
license_affected = NULL;

if ("CE Enterprise" >< license || "Vista Enterprise" >< license || report_paranoia == 2) license_affected = TRUE;

if (ver_compare(ver:version, fix:"8.0.6", strict:FALSE) <= 0 && license_affected)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_loc +
      '\n  Installed version : ' + version + " (" + license + ")" +
      '\n  Fixed version     : Refer to the vendor for a fix.' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version + " (" + license + ")");
