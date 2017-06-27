#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76494);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/12 14:46:29 $");

  script_cve_id("CVE-2014-2741");
  script_bugtraq_id(66717);
  script_osvdb_id(105419);
  script_xref(name:"CERT", value:"495476");

  script_name(english:"Openfire < 3.9.2 XMPP-Layer DoS");
  script_summary(english:"Checks Openfire version from admin login page.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a denial
of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Openfire prior to 3.9.2. It
is, therefore, affected by an XMPP-layer denial of service
vulnerability.

The vulnerability exists in 'nio/XMLLightweightParser.java' which
fails to properly restrict the processing of compressed XML elements,
which allows remote attackers to consume resources via a crafted XMPP
stream, known as an 'xmppbomb' attack.");
  script_set_attribute(attribute:"see_also", value:"https://community.igniterealtime.org/thread/52317");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.9.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:igniterealtime:openfire");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("openfire_console_detect.nasl");
  script_require_keys("www/openfire_console", "Settings/ParanoidReport");
  script_require_ports("Services/www", 9090);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

port = get_http_port(default:9090);

install = get_install_from_kb(appname:'openfire_console', port:port, exit_on_fail:TRUE);

dir = install['dir'];
ver = install['ver'];
prod = 'Openfire';

fix = '3.9.2';

if (isnull(ver)) audit(AUDIT_UNKNOWN_APP_VER, prod);

# nb: banner checks of open source software are prone to false-
#     positives so only run the check if reporting is paranoid.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + build_url(port:port, qs:dir+"/") +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, prod, ver);
