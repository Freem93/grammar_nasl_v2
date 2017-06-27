#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

prod = "Novell GroupWise Admin Console";

if (description)
{
  script_id(77474);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 21:17:13 $");

  script_cve_id("CVE-2014-0600");
  script_bugtraq_id(69424);
  script_osvdb_id(110461);

  script_name(english:"Novell GroupWise 'FileUploadServlet' Arbitrary File Access Vulnerability");
  script_summary(english:"Attempts to access the vulnerable script.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by an arbitrary file access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Novell GroupWise administration console is affected by an
arbitrary file access vulnerability that allows attackers to access
and delete arbitrary files on the affected system.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-296/");
  script_set_attribute(attribute:"see_also",value:"http://www.novell.com/support/kb/doc.php?id=7015566");
  script_set_attribute(attribute:"solution", value:"Upgrade to GroupWise 2014 SP1 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("novell_groupwise_admin_console_detect.nbin");
  script_require_ports("Services/www", 9710);
  script_require_keys("installed_sw/" + prod);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:9710);

get_install_count(app_name:prod, exit_if_zero:TRUE);

install = get_single_install(
  app_name : prod,
  port     : port
);

boundary = "---------------------------nessus";
postdata =
    '--' + boundary + '\r\n' +
    'Content-Disposition: form-data; name="poLibMaintenanceFileSave"\r\n' +
    '\r\n' + rand_str(length:30) + '\r\n' +
    '--' + boundary + '--\r\n';

res = http_send_recv3(
  method: "POST",
  item: "/gwadmin-console/gwAdminConsole/fileUpload",
  port: port,
  add_headers: make_array("Content-Type", "multipart/form-data; boundary=" + boundary),
  data: postdata,
  exit_on_fail: TRUE
);

if('filename="gwcheck.opt"' >< res[1] && 'login.jsp' >!< res[1])
{
  if(report_verbosity > 0)
  {
    url = build_url(port:port, qs:'/gwadmin-console/gwAdminConsole/fileUpload');

    report = '\nNessus was able to access the vulnerable script without authentication :\n' +
             '\n  ' + url + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, prod, port);
