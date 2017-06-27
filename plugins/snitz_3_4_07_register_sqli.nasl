#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40470);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2003-0286");
  script_bugtraq_id(35764);
  script_osvdb_id(4638, 56166);
  script_xref(name:"Secunia", value:"35733");

  script_name(english:"Snitz Forums 2000 <= 3.4.07 register.asp 'Email' Parameter SQL Injection");
  script_summary(english:"Attempts a SQL injection attack");

  script_set_attribute(  attribute:"synopsis",  value:
"The discussion forum running on the remote web server has a SQL
injection vulnerability."  );
  script_set_attribute( attribute:"description",  value:
"The remote version of Snitz Forums 2000 is vulnerable to a SQL
injection attack.  The domain name of the email address passed to
the 'Email' parameter of 'register.asp' is not sanitized before being
used in a SQL query.  A remote attacker could exploit this to execute
arbitrary SQL queries.

Note this checks for a different vulnerability than BID 7549 (covered
by Nessus plugins 14227 and 11621), even though the same parameter
and page are affected."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://forum.snitz.com/forum/topic.asp?TOPIC_ID=68812"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Apply the patch referenced in the vendor's security notice."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/03");
 script_cvs_date("$Date: 2016/05/13 15:33:30 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:snitz_communications:snitz_forums_2000");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("snitz_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/snitz");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_asp(port:port))
  exit(0, "The web server is not capable of hosting ASP applications.");

install = get_kb_item('www/' + port + '/snitz');
if (isnull(install)) exit(0, "Snitz wasn't detected on the remote host.");

match = eregmatch(string:install, pattern:'^.+ under (/.*)$');
if (isnull(match)) exit(1, "Unable to extract Snitz directory from the KB.");
dir = match[1];

# Make sure register.asp exists before attempting the injection attack
url = string(dir, '/register.asp');
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server didn't respond to the GET request.");

if ('<form action="register.asp?mode=Register"' >!< res[2])
  exit(0, "register.asp wasn't detected in the remote Snitz install.");

# Request number one - agree to ToS, get a cookie, and a token.
url = string(dir, '/register.asp?mode=Register');
headers = make_array('Content-Type', 'application/x-www-form-urlencoded');
postdata = 'policy_accept=true';
  
res = http_send_recv3(
  method:"POST",
  item:url,
  port:port,
  data:postdata,
  add_headers:headers
);
if (isnull(res)) exit(1, "The web server didn't respond to POST request #1.");

# Extract the token from the first response
pattern = '<input name="([^"]+)" type="hidden" value="[^"]+">';
match = eregmatch(string:res[2], pattern:pattern);
if (match) token = match[1];
else exit(1, 'Unable to extract token from first POST response.');

# Request number two - attempt SQL injection PoC
url = string(dir, '/register.asp?mode=DoIt');
sqli = string("@", SCRIPT_NAME, "'");
sqli_encoded = urlencode(str:sqli);

postdata = string(
  token, '=', token, '&',
  'Email=', sqli_encoded, '&',
  'Submit1=Submit'
);
res = http_send_recv3(
  method:"POST",
  item:url,
  port:port,
  add_headers:headers,
  data:postdata
);
if (isnull(res)) exit(1, "The web server didn't respond to POST request #2.");

# If the page has an ODBC error code, the PoC probably worked.
if ("error '80040e14'" >< res[2])
{
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

  if (report_verbosity > 0)
  {
    url = string(dir, '/register.asp?mode=Register');

    report = string(
      "\n",
      "Nessus detected this by going to the following URL :\n\n",
      "  ", build_url(qs:url, port:port), "\n\n",
      "accepting the privacy agreement, registering with the email address :\n\n",
      "  ", sqli, "\n\n",
      "and verifying the resulting error message.\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "This version of Snitz doesn't appear to be vulnerable.");
