#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18055);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-1134");
  script_bugtraq_id(13161);
  script_osvdb_id(15542);

  script_name(english:"Serendipity exit.php Multiple Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The version of Serendipity installed on the remote host allows an
attacker to pass arbitrary SQL code through the 'url_id' and
'entry_id' parameters of the 'exit.php' script.  These flaws may lead
to the disclosure / modification of data or attacks against the 
underlying database application." );
 script_set_attribute(attribute:"see_also", value:"http://www.s9y.org/63.html#A9" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Serendipity 0.7.1 / 0.8 or greater." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/13");
 script_cvs_date("$Date: 2012/07/12 19:24:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:s9y:serendipity");
script_end_attributes();

  script_summary(english:"Checks for SQL injection vulnerabilities in Serendipity exit.php");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
  script_dependencies("serendipity_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/serendipity");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/serendipity"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  dir = matches[2];

  # If safe checks are enabled...
  if (safe_checks()) {
    # nb: versions 0.7 and lower as well as 0.8-beta6 and
    #     lower may be vulnerable.
    if (ver =~ "0\.([1-6]|7([^0-9]|$)|8-beta[1-6])")
    {
     security_hole(port);
     set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    }
  }
  # Otherwise...
  else {
    # Try to exploit the vulnerability.
    w = http_send_recv3(method:"GET", 
      item:string(
        dir, "/exit.php?",
        "entry_id=1&",
        # This should issue a redirect to 'nessus'.
        "url_id=1%20UNION%20SELECT%20'nessus'--"
      ),
      port:port
    );
    if (isnull(w)) exit(1, "The web server did not answer");

    # There's a problem if there's a redirect to 'nessus'.
    if (
      ereg(string:w[0], pattern:"^HTTP/1\.1 301") &&
      egrep(string:w[1], pattern:"^Location: nessus")
    ) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
