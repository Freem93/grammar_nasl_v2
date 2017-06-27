#
# (C) Tenable Network Security, Inc.
#

# Thanks to OSVDB for the PoC.


include("compat.inc");


if (description)
{
  script_id(42352);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/01/14 20:12:25 $");

  script_cve_id("CVE-2009-1987");
  script_bugtraq_id(35691);
  script_osvdb_id(55909);

  script_name(english:"PeopleSoft PeopleTools JMS Listening Connector Activity Parameter XSS");
  script_summary(english:"Tries to inject script code into JMS Listening Connector Administrator interface");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts an application that is prone to a
cross-site scripting attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote web server is running an instance of PeopleSoft PeopleTools
that fails to sanitize user-supplied input to the 'Activity' parameter
on submission to the JMS Listening Connector Administrator interface
before using it to generate dynamic HTML output.  An attacker may be
able to leverage this to inject arbitrary HTML and script code into a
user's browser to be executed within the security context of the
affected site."
  );
   # http://www.oracle.com/technetwork/topics/security/whatsnew/index.html
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.nessus.org/u?e1e87349"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to version 8.49.22 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:peoplesoft_enterprise_peopletools");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 3000);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:3000);


# Unless we're being paranoid, make sure the banner looks like PeopleSoft.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (! banner) exit(1, "No HTTP banner on port "+port);
  if ("X-Powered-By: Servlet/" >!< banner) exit(0, "Server response header on port "+port+" suggests it's not PeopleSoft.");
}


# Try to exploit the issue.
alert = string("alert('", SCRIPT_NAME, "');");
test_cgi_xss(
  port     : port,
  cgi      : "/JMSListeningConnectorAdministrator",
  dirs     : make_list("/PSIGW"),
  qs       : "Activity="+urlencode(str:alert),
  pass_str : alert,
  pass2_re : "<H3>JMSListeningConnector"
);
