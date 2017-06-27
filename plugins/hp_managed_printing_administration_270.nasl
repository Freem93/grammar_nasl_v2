#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66273);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/23 22:03:55 $");

  script_cve_id("CVE-2012-5219");
  script_bugtraq_id(59510);
  script_osvdb_id(92797);
  script_xref(name:"IAVA", value:"2013-A-0096");

  script_name(english:"HP Managed Printing Administration < 2.7.0 XSS");
  script_summary(english:"Checks version of HP Managed Printing Administration");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an ASP application that is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server is hosting a version of HP Managed Printing
Administration earlier than 2.7.0.  As such, it is potentially affected
by an unspecified cross-site scripting vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-093/");
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03737200
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c73dd381");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP Managed Printing Administration 2.7.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:managed_printing_administration");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("hp_managed_printing_administration_detect.nasl");
  script_require_keys("www/hp_managed_printing_administration");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, asp:TRUE);

install = get_install_from_kb(appname:'hp_managed_printing_administration', port:port, exit_on_fail:TRUE);
dir = install['dir'];
version = install['ver'];

url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, 'HP Managed Printing Administration', url);

# Versions < 2.7.0 are affected
if (ver_compare(ver:version, fix:'2.7.0') == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.7.0 \n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'HP Managed Printing Administration', url, version);
