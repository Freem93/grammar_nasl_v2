#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 5201 ) exit(0, "webmirror3.nbin is required.");

include("compat.inc");

if(description)
{
 script_id(91815);
 script_version ("$Revision: 1.1 $");
 script_cvs_date("$Date: 2016/06/24 15:48:48 $");

 script_name(english:"Web Application Sitemap");
 script_summary(english:"Reports pages that that are crawled by Nessus.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts linkable content that can be crawled by
Nessus.");
 script_set_attribute(attribute:"description", value:
"The remote web server contains linkable content that can be used to
gather information about a target.");
 # https://www.owasp.org/index.php/Testing:_Spidering_and_googling#Spidering
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5496c8d9");
 script_set_attribute(attribute:"solution", value:"n/a");
 
 script_set_attribute(attribute:"risk_factor", value: "None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Web Servers");

 script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("xml_func.inc");
include("http.inc");

port = get_http_port(default: 80, embedded: TRUE);
urls = make_list();

# Fix for webmirror_uri "no such table" errors 
table = query_scratchpad("SELECT name FROM sqlite_master where type = 'table' and name = 'webmirror_uri'");
if (empty_or_null(table)) exit(1, "Unable to obtain webmirror_uri table from webmirror crawl.");

# Query Scratchpad for webmirror results with a status code of 200
# and load results into urls list
res = query_scratchpad("SELECT DISTINCT uri FROM webmirror_uri WHERE port = ? AND status_code = 200 ORDER BY uri ASC", port);
if (empty_or_null(res)) exit(1, 'Unable to obtain crawled URIs from webmirror scratchpad.');
foreach url (res)
{
  # Filter out Apache directory listings page sorting
  if (url['uri'] !~ "/\?[CO]\=[NDMSA](%|$)") urls = make_list(urls, url['uri']);
}
if (empty_or_null(urls)) exit(1, 'No URLs were found during the crawl to build a sitemap.');

# Build text report (report) and Sitemap XML attachment (sitemap_xml)
report = '\nThe following sitemap was created from crawling linkable content on the target host :\n\n';
sitemap_xml =
  '<?xml version="1.0" encoding="UTF-8"?>' + '\n' +
  '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + '\n';

foreach url (urls)
{
  report += '  - ' + build_url(qs:url, port:port) + '\n';
  sitemap_xml +=
    '    <url>' + '\n' +
    '        <link>' + xml_escape(build_url(qs:url, port:port)) + '</link>' + '\n' +
    '    </url>' + '\n';
}

report += '\n' + 'Attached is a copy of the sitemap file.' + '\n';
sitemap_xml +=
  '</urlset>';

attachments = make_list();
attachments[0] = make_array();
attachments[0]["type"] = "application/xml";
attachments[0]["name"] = get_host_name() + "_" + port + "_sitemap.xml";
attachments[0]["value"] = sitemap_xml;
security_report_with_attachments(
  port  : port,
  level : 0,
  extra : report,
  attachments : attachments
);
exit(0);
