#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 5201 ) exit(0, "webmirror3.nbin is required.");

include("compat.inc");

if(description)
{
  script_id(85582);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");


  script_name(english:"Web Application Potentially Vulnerable to Clickjacking");
  script_summary(english:"Reports pages with clickable events that don't use X-Frame-Options or Content-Security-Policy header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server may fail to mitigate a class of web application
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote web server does not set an X-Frame-Options response header
or a Content-Security-Policy 'frame-ancestors' response header in all
content responses. This could potentially expose the site to a
clickjacking or UI redress attack, in which an attacker can trick a
user into clicking an area of the vulnerable page that is different
than what the user perceives the page to be. This can result in a user
performing fraudulent or malicious transactions.

X-Frame-Options has been proposed by Microsoft as a way to mitigate
clickjacking attacks and is currently supported by all major browser
vendors.

Content-Security-Policy (CSP) has been proposed by the W3C Web
Application Security Working Group, with increasing support among
all major browser vendors, as a way to mitigate clickjacking and other
attacks. The 'frame-ancestors' policy directive restricts which
sources can embed the protected resource.

Note that while the X-Frame-Options and Content-Security-Policy
response headers are not the only mitigations for clickjacking, they
are currently the most reliable methods that can be detected through
automation. Therefore, this plugin may produce false positives if
other mitigation strategies (e.g., frame-busting JavaScript) are
deployed or if the page does not perform any security-sensitive
transactions.");
  # https://software-security.sans.org/blog/2009/10/15/adoption-of-x-frame-options-header/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?399b1f56");
  script_set_attribute(attribute:"see_also", value:"https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Clickjacking");
  script_set_attribute(attribute:"solution", value:
"Return the X-Frame-Options or Content-Security-Policy (with the
'frame-ancestors' directive) HTTP header with the page's response.
This prevents the page's content from being rendered by another site
when using the frame or iframe HTML tags.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(693);
  # Protection Mechanism Failure

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencie("webmirror.nasl");
  script_require_ports("Services/www");
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80, embedded: TRUE);
hdr_list = make_list();
vuln_list = make_list();

xfo_list = get_kb_list("www/"+port+"/header/missing/x-frame-options");
if (empty_or_null(xfo_list))
 exit(0, "X-Frame-Options response headers were seen from the web server on port "+port+".");
xfo_list = sort(list_uniq(make_list(xfo_list)));


csp_list = get_kb_list("www/"+port+"/header/missing/csp-frame-ancestors");
if (empty_or_null(csp_list))
 exit(0, "Content-Security-Policy response headers were seen from the web server on port "+port+".");
csp_list = sort(list_uniq(make_list(csp_list)));


click_list = get_kb_list("www/"+port+"/content/clickable-event/*");
if (empty_or_null(click_list))
 exit(0, "No clickable events were seen from the web server on port "+port+".");
click_list = sort(list_uniq(make_list(click_list)));

# Loop through pages that are missing X-Frame-Options headers
# and add the intersections with pages that are missing 
# Content-Security-Policy headers to hdr_list
foreach xfo_url (xfo_list)
{
  foreach csp_url (csp_list)
  {
    if(csp_url == xfo_url) hdr_list = make_list(hdr_list, csp_url);
  }
}

# Loop through pages that are missing Content-Security-Policy headers
# and add the intersections with pages that are missing
# X-Frame-Options headers to hdr_list
foreach csp_url (csp_list)
{
  foreach xfo_url (xfo_list)
  {
    if(xfo_url == csp_url) hdr_list = make_list(hdr_list, xfo_url);
  }
}

# Sort unique header urls and verify we're not continuing
# execution with an empty/null hdr_list
hdr_list = sort(list_uniq(hdr_list));
if(empty_or_null(hdr_list)) exit(0, "No URLs are missing clickjacking mitigation headers.");

# Loop through pages that have a click event (form, onclick, flash object, etc)
# and add the intersections with pages that are missing
# X-Frame-Options and Content-Security-Policy headers to vuln_list
foreach click_url (click_list)
{
  foreach hdr_url (hdr_list)
  {
    if (hdr_url == click_url) vuln_list = make_list(vuln_list, hdr_url);
  }
}

# Loop through pages that are missing X-Frame-Options and Content-Security-Policy
# headers and add the intersections with pages that are missing a click
# event (form, onclick, flash object, etc)
foreach hdr_url (hdr_list)
{
  foreach click_url (click_list)
  {
    if (click_url == hdr_url) vuln_list = make_list(vuln_list, hdr_url);
  }
}

# Sort unique vuln urls and verify we're not continuing
# execution with an empty/null vuln_list
vuln_list = sort(list_uniq(vuln_list));
if(empty_or_null(vuln_list)) exit(0, "No URLs with clickable events were detected that were also missing clickjacking mitigation headers.");

# If we've reached this point, we can safely report without risk
# of empty results
report = '\nThe following pages do not use a clickjacking mitigation response header and contain a clickable event :\n\n';
foreach vuln_url (sort(list_uniq(vuln_list))) report = strcat(report, '  - ', build_url(qs:vuln_url, port:port), '\n');
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
exit(0);
