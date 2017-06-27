#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53297);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_name(english:"Adobe ColdFusion Admin Requires No Authentication");
  script_summary(english:"Checks if the ColdFusion admin area requires authentication.");

  script_set_attribute(attribute:"synopsis", value:
"ColdFusion administration does not require authentication.");
  script_set_attribute(attribute:"description", value:
"The version of ColdFusion running on the remote host allows access
to its administration pages without authentication.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/coldfusion-family.html");
  script_set_attribute(attribute:"solution", value:
"Configure ColdFusion administration to require authentication. This
setting may be found in the ColdFusion administration menu under
'Security'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:coldfusion");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("coldfusion_detect.nasl");
  script_require_keys("installed_sw/ColdFusion");
  script_require_ports("Services/www", 80, 8500);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

app = 'ColdFusion';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);
admin_requires_no_auth = get_kb_item_or_exit("www/"+port+"/coldfusion/no_admin_password");

if (admin_requires_no_auth)
{
  if (report_verbosity > 0)
  {
    report = get_vuln_report(
      items : '/CFIDE/administrator/index.cfm',
      port  : port
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The "+app+" administration pages on port "+port+" are not accessible without authentication.");
