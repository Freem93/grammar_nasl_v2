#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83475);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/25 14:28:28 $");

  script_cve_id("CVE-2015-1773");
  script_bugtraq_id(73954);
  script_osvdb_id(120386);

  script_name(english:"Adobe/Apache Flex ASDoc Tool XSS");
  script_summary(english:"Checks for vulnerable source code.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains HTML documents that are affected by a
cross-site scripting vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote web server contains one or more HTML documents created
with an unpatched version of the Adobe/Apache Flex ASDoc tool that is
potentially affected by a cross-site scripting vulnerability due to a
failure to properly sanitize user input.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flex/apsb15-08.html");
  script_set_attribute(attribute:"see_also", value:"https://blogs.apache.org/flex/entry/apache_flex_4_14_1");
  script_set_attribute(attribute:"solution", value:
"Update the affected files in the case of Adobe Flex. For Apache Flex,
either upgrade to Apache Flex 4.14.1 or update the affected files.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"patch_publication_date", value: "2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flex_sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:flex");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

# In the case of Adobe Flex, there is nothing to
# really indicate that it is indeed Adobe Flex
# rather than any other generic application. The
# same goes for Apache Flex.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app  = "Adobe/Apache Flex";
port = get_http_port(default:80);
item = '/index.html';
vuln = FALSE;

dirs = make_list('/asdoc');
if (thorough_tests) dirs = list_uniq(make_list(dirs, cgi_dirs()));

foreach dir (dirs)
{
  url = dir + item;

  res = NULL;
  res = http_send_recv3(method:"GET", item:url, port:port);
  if (empty_or_null(res)) continue;

  fix = NULL;
  if ('<title>API Documentation</title>' >< res[2]) fix = 'See vendor advisory.';
  else if ('<title>ActionScrip' >< res[2]) fix = 'Apache Flex 4.14.1';

  if (
    !isnull(fix) &&
    'd=document.location.search' >< res[2] &&
    'd2=decodeURIComponent(document.location.search).toLowerCase()' >!< res[2]
  )
  {
    set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
    if (report_verbosity > 0)
    {
      report_url = build_url(qs:url, port:port);
      report =
        '\n  URL           : ' + report_url +
        '\n  Fixed version : ' + fix +
        '\n  PoC URL       : ' + report_url + '?javascript:alert(1)&index-list.html' +
        '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    vuln = TRUE;
  }
}

if (!vuln) audit(AUDIT_HOST_NOT, "affected");
