#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(15562);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2014/09/22 17:06:55 $");

 script_cve_id("CVE-2004-1634", "CVE-2004-1635");
 script_bugtraq_id(11511);
 script_osvdb_id(11115, 11116);
 script_xref(name:"Secunia", value:"12939");

 script_name(english:"Bugzilla < 2.16.7 / 2.18.0rc3 Multiple Information Disclosures");
 script_summary(english:"Checks Bugzilla version number");

 script_set_attribute(attribute:"synopsis", value:
"The remote bug tracker has multiple information disclosure
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote Bugzilla bug tracking system, according to its version
number, is vulnerable to various flaws that may let an attacker bypass
authentication or get access to private bug reports.");
 script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/2.16.6/");
 script_set_attribute(attribute:"solution", value:"Upgrade to version 2.16.7 / 2.18.0rc3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/25");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");

 script_dependencie("bugzilla_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("installed_sw/Bugzilla", "Settings/ParanoidReport");

 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Bugzilla';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

# Check the installed version.
install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

version = install['version'];
dir = install['path'];
install_loc = build_url(port:port, qs:dir+'/query.cgi');

if(ereg(pattern:"^(1\..*)|(2\.(0\..*|1[0-3]\..*|14\..*|15\..*|16\.[0-6]|17\..*|18\.0 *rc[0-2]))[^0-9]*$",
       string:version))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version : ' + version +
      '\n  URL     : ' + install_loc;
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
