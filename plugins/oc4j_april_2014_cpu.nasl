#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(74120);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/08 22:17:48 $");

  script_cve_id("CVE-2014-0413", "CVE-2014-0414", "CVE-2014-0426");
  script_bugtraq_id(66831, 66852, 66859);
  script_osvdb_id(105832, 105833, 105834);

  script_name(english:"Oracle Containers for J2EE Multiple Unspecified HTTP Vulnerabilities (April 2014 CPU)");
  script_summary(english:"Checks for April 2014 patch");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote install of Oracle Containers for
J2EE is missing a vendor-supplied update. It is, therefore, affected
by multiple, unspecified vulnerabilities related to how HTTP requests
are handled.");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2014-1972952.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef1fc2a6");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("oc4j_detect.nbin");
  script_require_ports("Services/www", 8888, 8080, 80);
  script_require_keys("www/oc4j");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = "Oracle Containers for J2EE";

port = get_http_port(default:8888);
version = get_kb_item_or_exit("www/" + port + "/oc4j/version");
if (version == "unknown") audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app, port);

# 10.1.3.5.0 is only affected supported version
if (version !~ "^10\.1\.3\.5(\.0)?$") audit(AUDIT_LISTEN_NOT_VULN, app, port, version);

# the patch limits POST request buffers for form auth to 4096 bytes
# sending one or more bytes will trigger an exception.
postdata = crap(data:"0", length:4097);

res = http_send_recv3(
  method:'POST',
  # try to test if install is patched by sending request
  # enterprise manager servlet that is installed by default
  item:'/em/console',
  data:postdata,
  content_type:'application/x-www-form-urlencoded',
  port:port,
  exit_on_fail:TRUE
);

# unpatched installs will display login page
if ('<title>Login to Oracle Application Server Control</title>' >< res[2])
{
  if (report_verbosity > 0)
  {
    report = '\n  Version        : ' + version +
             '\n  Required Patch : 18272621 / 18272678 / 18272679 / 18272681\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}

# check that servlet exists (for audit trail)
res = http_send_recv3(
  method:'POST',
  item:'/em/console',
  port:port,
  data:"",
  content_type:'application/x-www-form-urlencoded',
  exit_on_fail:TRUE
);

if ('<title>Login to Oracle Application Server Control</title>' >< res[2]) audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
else exit(0, "Unable to find Enterprise Manager servlet on the application server listening on port " + port + ".");
