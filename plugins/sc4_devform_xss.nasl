#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70216);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/13 15:33:29 $");

  script_cve_id("CVE-2013-5911");
  script_bugtraq_id(62609);
  script_osvdb_id(97584);

  script_name(english:"SecurityCenter devform.php message Parameter XSS");
  script_summary(english:"Checks for existence of devform.php script.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that is affected by a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Tenable Network Security SecurityCenter installed on the
remote host contains the 'devform.php' script.  This PHP script is
affected by a cross-site scripting vulnerability because the application
does not properly validate user-supplied input to the 'message'
parameter.  An attacker could leverage this to inject arbitrary HTML and
script code into a user's browser to be executed within the security
context of the affected site."
  );
  script_set_attribute(attribute:"see_also", value:"https://support.tenable.com/support-center/advisory.php");
  script_set_attribute(attribute:"solution", value:"Remove the 'devform.php' script or restrict access to the script.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:security_center");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:443, php:TRUE);

report_url = build_url(qs:"/", port:port);
app = "Tenable Network Security SecurityCenter";

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : "/",
  exit_on_fail : TRUE
);

if (
  "<title>Tenable Network Security</title>" >!< res[2] &&
  'attributes.id = "SC4Main";' >!< res[2]
) audit(AUDIT_WEB_APP_NOT_INST, app, port);

res2 = http_send_recv3(
  method : "GET",
  port   : port,
  item   : "/devform.php",
  exit_on_fail : TRUE
);
if (
  "title>Security Center Development Form" >< res2[2] &&
  "function sendMessageToFrame" >< res2[2] &&
  'class="bodyTitle">Security Center Development Form' >< res2[2]
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
     '\n' + 'Nessus was able to verify this issue by checking for the existence' +
     '\n' + 'of "/devform.php" using the following URL :' +
     '\n' +
     '\n' + report_url + "devform.php" +
     '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, report_url);
