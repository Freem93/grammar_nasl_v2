#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50599);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2010-3172");
  script_bugtraq_id(44618);
  script_osvdb_id(69221);

  script_name(english:"Bugzilla Response Splitting");
  script_summary(english:"Look for response splitting flaw.");

  script_set_attribute(attribute:"synopsis", value:"A web application is affected by a response splitting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Bugzilla hosted on the remote web server allows
injection of arbitrary HTTP headers and content when Server Push is
enabled in a browser.

Note that the install also likely creates restricted reports in a
known location and with predictable names, which can lead to a loss
of information, although Nessus has not checked for this."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/3.2.8/");
  script_set_attribute(attribute:"solution", value:"Update to Bugzilla 3.2.9 / 3.4.9 / 3.6.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencie("bugzilla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Bugzilla");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

global_var	hd, output, attack_req1, attack_req2;

hd = make_array(
"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
"Accept-Language", "en-us;q=0.5,en;q=0.3",
# The User-Agent is necessary to trigger the right behavior
"User-Agent", "Mozilla/5.0 (X11; U; Linux i686 (x86_64); fr; rv:1.9.1.10) Gecko/20100504 Firefox/3.5.10",
"Accept-Charset", "ISO-8859-1,utf-8;q=0.7,*;q=0.7");

function extract_boundaries(port, u)
{
  local_var	w, loc, v, l, b, boundaries;

  w = http_send_recv3(method:"GET", item: u, port: port, add_headers: hd, exit_on_fail: 1);
  if (w[0] !~ "^HTTP/[0-9.]+ +200 ") return NULL;

  # No need to set follow_redirect, we have to issue a GET after that.
  w = http_send_recv3(method:"POST", item: u, port: port, exit_on_fail: 1,
    content_type: "application/x-www-form-urlencoded", add_headers: hd,
    data: "query_format=advanced&short_desc_type=allwordssubstr&short_desc=&longdesc_type=allwordssubstr&longdesc=&bug_file_loc_type=allwordssubstr&bug_file_loc=&bug_status=NEW&bug_status=ASSIGNED&bug_status=REOPENED&emailassigned_to1=1&emailtype1=substring&email1=&emailassigned_to2=1&emailreporter2=1&emailcc2=1&emailtype2=substring&email2=&bug_id_type=anyexact&bug_id=&votes=&chfieldfrom=&chfieldto=Now&chfieldvalue=&cmdtype=doit&order=Reuse+same+sort+as+last+time&field0-0-0=noop&type0-0-0=noop&value0-0-0=");

  attack_req1 = http_last_sent_request();
  if (w[0] =~ "^HTTP/[0-9.]+ 30[12] ")
  {
    loc = egrep (string: w[1], pattern:"^Location:", icase: 1);
    if (!loc) return NULL;
    v = eregmatch(string: chomp(loc), pattern: "^Location: *(https?://[^/]+(:[0-9]+)?)?(/.*)");
    if (isnull(v)) return NULL;
    u = v[3];
    w = http_send_recv3(method:"GET", item: u, port: port, exit_on_fail: 1, add_headers: hd);
    attack_req2 = http_last_sent_request();
  }
  if (w[0] !~ "^HTTP/[0-9.]+ +200 ") return NULL;

  boundaries = egrep(string: w[2], pattern: "^--------- =");
  if (!boundaries) return NULL;

  foreach b (split(boundaries, keep: 0))
  {
    v = eregmatch(string: b, pattern: "^--------- *=([^-]+(-+)$)");
    if (!isnull(v))
    {
      l = v[1];
      output = strstr(w[2], l);
      break;
    }
  }
  if (empty_or_null(l)) return NULL;
  return l;
}

app = 'Bugzilla';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default: 80, embedded: 0);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_loc = build_url(port:port, qs:dir);

u = dir + "/buglist.cgi?query_format=advanced";
b = extract_boundaries(port: port, u: u);
if (isnull(b)) exit(0, "Output is not multipart.");

if (b =~ '_aaaaaaaaaa0(--)?')	# Default boundary
{
  b2 = extract_boundaries(port: port, u: u);
  if (isnull(b2)) exit(1, "Output is not multipart.");

  if (b == b2)	# Constant boundary
  {
    security_report_v4(
      port       : port,
      severity   : SECURITY_WARNING,
      generic    : TRUE,
      line_limit : 5,
      request    : make_list(attack_req1, attack_req2),
      output     : output
    );
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc);
