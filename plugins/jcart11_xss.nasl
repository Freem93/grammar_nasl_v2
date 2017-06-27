#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(55775);
 script_version("$Revision: 1.8 $");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");

 script_bugtraq_id(43639);
 script_osvdb_id(68326);
 script_xref(name:"EDB-ID", value: "15171");

 script_name(english: "jCart 1.1 my-item-name POST Parameter XSS ");
 script_summary(english: "XSS in jcart-relay.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by a
cross-site scripting vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server hosts jCart. 

Nessus was able to trigger a cross-site scripting vulnerability
against one of the PHP scripts. 

In addition, this web application is likely to be affected by
uncontrolled redirection and affected by cross-site request forgery
vulnerabilities, although Nessus has not checked for them." );
 script_set_attribute(attribute:"see_also", value:
"http://conceptlogic.com/jcart/help/viewtopic.php?f=6&t=669");
 script_set_attribute(attribute:"solution", value:
"Upgrade to jCart 1.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(
  79,  # Cross-Site Scripting
  80,  # Improper Neutralization of Script-Related HTML Tags in a Web Page Basic XSS
  928, # Weaknesses in OWASP Top Ten 2013
  931  # OWASP Top Ten 2013 Category A3 - Cross-Site Scripting XSS
  );

 script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/01");
 script_set_attribute(attribute:"patch_publication_date", value:"2010/10/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/08");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses : XSS");

 script_dependencie("http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (get_kb_item("Settings/disable_cgi_scanning"))
  exit(0, "Settings/disable_cgi_scanning is set.");

attack = '</td></form><script>alert(42);</script>';

port = get_http_port(default: 80, embedded: 0, php: 1);

dirs = cgi_dirs();
if (isnull(dirs)) dirs = make_list("/jcart", "/");
else if (thorough_tests)
  dirs = list_uniq(make_list("/jcart", "/", dirs));

installed = 0;
foreach dir (dirs)
{
  u = dir;
  l = strlen(u); if (l == 0) continue;
  if (u[l - 1 ] != "/") u += "/";
  css = u + "jcart.css";
  u += "jcart-relay.php";
  w = http_send_recv3(port: port, item: u, method:"GET", exit_on_fail: 1);
  if (w[0] !~ "^HTTP/1\.[01] +200" ||
      "<form method='post' action='checkout.php'>" >!< w[2] ||
      "<!-- BEGIN JCART -->" >!< w[2]) continue;
  installed ++;

  w = http_send_recv3(method: "POST", item: u, port: port, 
  content_type: "application/x-www-form-urlencoded", exit_on_fail: 1,
  data: 'my-item-id=0&my-item-price=0.0&my-item-name='+attack+'&my-item-qty=1&my-add-button=add+to+cart');

  if (w[0] =~ "^HTTP/1\.[01] +200 " &&
      "<!-- BEGIN JCART -->" >< w[2])	
  {
    rep = extract_pattern_from_resp(string: w[2], pattern: "PA:*"+attack+"*");
    if (rep)
    {
      e = '\nThis CGI is vulnerable to a cross-site scripting attack :\n' 
        + build_url(port: port, qs: u) + '\n';

      w = http_send_recv3(method:"GET", port: port, item: css, exit_on_fail: 0);
      if (! isnull(w) && w[0] =~ "^HTTP/1\.[01] 200 ")
      {
        if (egrep(string: w[2], pattern: "^#jcart "))
	{
	  ver = egrep(string: w[2], pattern: "^JCART +v[0-9]");
	  if (ver && strlen(ver) < 80)
	    e += chomp(ver) + ' appears to be installed.\n';
	}
      }
      if (report_verbosity > 0)
      {
        e += '\nThe following request triggered the vulnerability :\n\n'
           + http_last_sent_request() + '\n';
        if (report_verbosity > 1)	
          e += '\nThe HTTP response contains :\n\n' + rep + '\n';
      }
      security_warning(port: port, extra: e);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      # set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
      exit(0);
    }
  }
}

if (installed)
  exit(0, "jcart-relay.php on port "+port+" is affected.");
else
  exit(0, "The vulnerable jcart-relay.php CGI was not found on port "+port+".");
