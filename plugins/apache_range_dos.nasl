#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55976);
  script_version("$Revision: 1.31 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id("CVE-2011-3192");
  script_bugtraq_id(49303);
  script_osvdb_id(74721);
  script_xref(name:"CERT", value:"405811");
  script_xref(name:"EDB-ID", value:"17696");
  script_xref(name:"EDB-ID", value:"18221");

  script_name(english:"Apache HTTP Server Byte Range DoS");
  script_summary(english:"Checks if any workarounds are being used");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The web server running on the remote host is affected by a
denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apache HTTP Server running on the remote host is
affected by a denial of service vulnerability.  Making a series of
HTTP requests with overlapping ranges in the Range or Request-Range
request headers can result in memory and CPU exhaustion.  A remote,
unauthenticated attacker could exploit this to make the system
unresponsive.

Exploit code is publicly available and attacks have reportedly been
observed in the wild."
  );
  script_set_attribute(attribute:"see_also",value:"http://seclists.org/fulldisclosure/2011/Aug/175");
  script_set_attribute(attribute:"see_also",value:"http://www.gossamer-threads.com/lists/apache/dev/401638");
  # http://mail-archives.apache.org/mod_mbox/httpd-announce/201108.mbox/%3C20110826103531.998348F82@minotaur.apache.org%3E
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?404627ec");
  script_set_attribute(attribute:"see_also",value:"http://httpd.apache.org/security/CVE-2011-3192.txt");
  # http://www.oracle.com/technetwork/topics/security/alert-cve-2011-3192-485304.html
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?1538124a");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg24030863");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Apache httpd 2.2.21 or later. Alternatively, apply one of
the workarounds in Apache's advisories for CVE-2011-3192. Version
2.2.20 fixed the issue, but it also introduced a regression.

If the host is running a web server based on Apache httpd, contact the
vendor for a fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
script_set_attribute(attribute:"vuln_publication_date",value:"2011/08/19");
  script_set_attribute(attribute:"patch_publication_date",value:"2011/08/25");
  script_set_attribute(attribute:"plugin_publication_date",value:"2011/08/25");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

global_var port;

# finds a page that responds with an HTTP 200 when we make a HEAD request
function find_200()
{
  local_var res, ext, exts, page, files;

  # try to reduce false negatives by checking content that is likely to be static
  exts = make_list('htm*', 'jp*g', 'png', 'css', 'js', 'ico', 'xml');
  foreach ext (exts)
  {
    files = get_kb_list('www/' + port + '/content/extensions/' + ext);
    if (isnull(files)) continue;

    # check one file per extension
    files = make_list(files);
    res = http_send_recv3(method:'HEAD', item:files[0], port:port);
    if (isnull(res)) continue;
    if (res[0] =~ "^HTTP/1\.[01] +200 ") return files[0];
  }

  # check the root as a last resort
  page = '/';
  res = http_get_cache(item:page, port:port);
  if (res =~ "^HTTP/1\.[01] +200 ") return page;

  return NULL;
}

port = get_http_port(default:80);

# Make sure this looks like Apache unless paranoid
if (report_paranoia < 2)
{
  server = http_server_header(port:port);

  if ( 'ibm_http_server' >!< tolower(server) && 'apache' >!< tolower(server) && 'oracle http server' >!< tolower(server) && 'oracle-http-server' >!< tolower(server) )
    exit(0, 'The web server on port ' + port + ' doesn\'t look like an Apache-based httpd');

  # looks like Apache _httpd_
  if ('apache' >< tolower(server) && ( 'coyote' >< tolower(server) || 'tomcat' >< tolower(server)) )
    exit(0, 'The web server on port ' + port + ' doesn\'t look like Apache httpd');
}

attempts = make_array();
url = find_200();
if (isnull(url))
  exit(1, 'Couldn\'t find a page on port ' + port + ' that responds to a HEAD with an HTTP 200.');

# This detects workarounds 1, 3, 4, or 5 from the advisory, but not the fix in 2.2.20
# Throw in an invalid range (5-0) which Apache httpd will accept, but non-vulnerable
# servers like IIS will ignore (responds to requests w/invalid ranges with 200 isntead of 206)
hdr = make_array(
  'Range', 'bytes=5-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9,10-10',
  'Request-Range', 'bytes=5-0,1-1,2-2,3-3,4-4,5-5,6-6,7-7,8-8,9-9,10-10'
);
res = http_send_recv3(method:'HEAD', item:url, add_headers:hdr, port:port, exit_on_fail:TRUE);

# If none of those four workarounds are in place, the server will return a 206 Partial Content
if (res[0] !~ "^HTTP/1\.[01] +206 ")
  exit(0, 'The server on port ' + port + ' didn\'t respond with a HTTP 206, it appears a workaround is being used.');
else
{
  attempts['workarounds']['request'] = http_last_sent_request();
  attempts['workarounds']['response'] = res[0] + res[1];
}

# Next, try testing the fix added to 2.2.20 (if sum of ranges are greater than the size of the page
# return the entire thing). Research indicates simply requesting a range of '0-' results in a 200 in
# 2.2.20. We'll request 0-,1- on the offchance that it will reduce the possibility of false negatives.
# This detects the fix in 2.2.20, but not the workarounds
hdr = make_array(
  'Range', 'bytes=0-,1-',
  'Request-Range', 'bytes=0-,1-'
);
res = http_send_recv3(method:'HEAD', item:url, add_headers:hdr, port:port, exit_on_fail:TRUE);

# Unpatched servers respond with a 206 (vs 200)
if (res[0] !~ "^HTTP/1\.[01] +206 ")
  exit(0, 'The server on port ' + port + ' didn\'t respond with a HTTP 206, it appears the system has been patched.');
else
{
  attempts['patch']['request'] = http_last_sent_request();
  attempts['patch']['response'] = res[0] + res[1];
}

if (report_verbosity > 0)
{
  report =
    '\nNessus determined the server is unpatched and is not using any' +
    '\nof the suggested workarounds by making the following requests :\n';

  foreach attempt (make_list('workarounds', 'patch'))
  {
    request = attempts[attempt]['request'];
    response = attempts[attempt]['response'];

    report +=
      '\n' +
      crap(data:'-', length:20) + ' Testing for ' + attempt + ' ' + crap(data:"-", length:20) + '\n' +
      request;

    report += chomp(response) + '\n'; # replace two crlf with one newline

    report += crap(data:'-', length:20) + ' Testing for ' + attempt + ' ' + crap(data:"-", length:20) + '\n';
  }

  security_hole(port:port, extra:report);
}
else security_hole(port);

