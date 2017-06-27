#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22300);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2017/01/30 23:05:17 $");

  script_cve_id("CVE-2006-4542");
  script_bugtraq_id(19820);
  script_osvdb_id(28337, 28338);

  script_name(english:"Webmin Null Byte Filtering Information Disclosure");
  script_summary(english:"Checks if nulls in a URL are filtered by 'miniserv.pl'.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Webmin installed on the remote host is affected by an
information disclosure vulnerability due to the Perl script
'miniserv.pl' failing to properly filter null characters from URLs. An
attacker could exploit this to reveal the source code of CGI scripts,
obtain directory listings, or launch cross-site scripting attacks
against the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www.lac.co.jp/business/sns/intelligence/SNSadvisory_e/89_e.html");
  script_set_attribute(attribute:"see_also", value:"http://www.webmin.com/security.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Webmin version 1.296 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:webmin:webmin");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("webmin.nasl");
  script_require_keys("www/webmin");
  script_require_ports("Services/www", 10000);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

app = 'Webmin';
port = get_http_port(default:10000, embedded: TRUE);
get_kb_item_or_exit('www/'+port+'/webmin');

dir = "/";
install_url = build_url(port:port, qs:dir);

# Some files don't require authentication; eg, those matching the
# pattern '^[A-Za-z0-9\\-/]+\\.gif'. So request a bogus gif file; if
# nulls are filtered, we'll get an error saying "Error - File not
# found"; otherwise, we'll get a login form because the null will
# cause the regex to fail.

# First send a request to the fake image and ensure we don't get a
# login page.  Prevents FP with earlier releases which don't respond
# to this attack method
filename = rand_str();

res = http_send_recv3(
  method : "GET",
  item   : dir + filename + ".gif",
  port   : port,
  fetch404 : TRUE,
  exit_on_fail : TRUE
);

if ("<form action=/session_login.cgi " >!< res[2])
{
  attack = filename + "%00.gif";
  res = http_send_recv3(
    method : "GET",
    item   : dir + attack,
    port   : port,
    exit_on_fail : TRUE
  );
  # There's a problem if we see a login form.
  if ("<form action=/session_login.cgi " >< res[2])
  {
     set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
     if (report_verbosity > 0)
     {
       report =
         '\n' + 'Nessus was able to verify this issue with the following URL :' +
         '\n' + 
         '\n' + install_url + attack + 
         '\n';
       security_warning(port:port, extra:report);
     }
     else security_warning(port);
     exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
