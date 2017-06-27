#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(11463);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2014/09/22 17:06:55 $");

 if ( NASL_LEVEL >= 3004 )
 {
  script_cve_id(
   "CVE-2002-0803",
   "CVE-2002-0804",
   "CVE-2002-0805",
   "CVE-2002-0806",
   "CVE-2002-0807",
   "CVE-2002-0808",
   "CVE-2002-0809",
   "CVE-2002-0810",
   "CVE-2002-0811",
   "CVE-2002-1196",
   "CVE-2002-1197",
   "CVE-2002-1198",
   "CVE-2002-2260",
   "CVE-2003-0012",
   "CVE-2003-0013"
  );
 }
 script_bugtraq_id(4964, 5842, 5843, 5844, 6257, 6501, 6502);
 script_osvdb_id(
  5080,
  6351,
  6352,
  6353,
  6354,
  6355,
  6356,
  6357,
  6394,
  6395,
  6397,
  6398,
  6399,
  6400,
  6401
 );

 script_name(english:"Bugzilla < 2.14.2 / 2.16rc2 / 2.17 Multiple Vulnerabilities (SQLi, XSS, ID, Cmd Exe)");
 script_summary(english:"Checks the Bugzilla version number");

  script_set_attribute(attribute:"synopsis", value:"The remote bug tracker has multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote Bugzilla bug tracking
system is vulnerable to various flaws, including SQL injection,
cross-site scripting, and arbitrary command execution.");
 script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/2.14.2/");
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.bugzilla.org/security/2.16/"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.bugzilla.org/security/2.16.1/"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.bugzilla.org/security/2.16.1-nr/"
 );
 script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla version 2.14.5 / 2.16.rc2 / 2.17.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/10/30");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/24");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");

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
url = build_url(port:port, qs:dir+'/query.cgi');

if(ereg(pattern:"^(1\..*)|(2\.(0\..*|1[0-3]\..*|14\.[0-4]|15\..*|16\.([0-1]|rc1)|17\.[0-2]))[^0-9]*$",
       string:version))
{
  set_kb_item('www/'+port+'/XSS', TRUE);
  set_kb_item('www/'+port+'/SQLInjection', TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Version : ' + version +
      '\n  URL     : ' + url;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
