#
# (C) Tenable Network Security, Inc.
#
# Ref:
# Date: Fri, 25 Apr 2003 04:40:33 -0400
# To: bugtraq@securityfocus.com, announce@bugzilla.org,
# From: David Miller <justdave@syndicomm.com>
# Subject: [BUGZILLA] Security Advisory - XSS, insecure temporary filenames


include("compat.inc");

if (description)
{
 script_id(11553);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2015/01/13 20:37:05 $");

 script_cve_id("CVE-2003-0602", "CVE-2003-0603");
 script_bugtraq_id(6861, 6868, 7412);
 script_osvdb_id(6348, 6349, 6350, 6383, 6384, 6385);

 script_name(english:"Bugzilla < 2.16.3 / 2.17.4 Multiple Vulnerabilities (XSS, Symlink)");
 script_summary(english:"Checks Bugzilla version number");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is affected by
several issues.");
 script_set_attribute(attribute:"description", value:
"The remote Bugzilla bug tracking system, according to its version
number, contains various flaws that may let an attacker perform cross-
site scripting attacks or even delete local files (provided he has an
account on the remote host).");
 script_set_attribute(attribute:"solution", value:"Upgrade to 2.16.3 / 2.17.4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/02/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/04/26");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("bugzilla_detect.nasl");
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

if(ereg(pattern:"^(1\..*)|(2\.(0\..*|1[0-3]\..*|14\..*|15\..*|16\.[0-2]|17\.[0-3]))[^0-9]*$",
       string:version))
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
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
