#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42191);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2009-3730");
  script_bugtraq_id(36721);
  script_osvdb_id(59088, 59089);
  script_xref(name:"Secunia", value:"37052");

  script_name(english:"IBM Rational RequisitePro ReqWebHelp Multiple XSS");
  script_summary(english:"Checks for XSS flaws in vulnerable pages");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts two JSP scripts that are affected by
cross-site scripting vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM Rational RequisitePro is installed on the remote host. 

The installed version contains two JSP scripts that are affected by
cross-site scripting vulnerabilities.  Specifically, it fails to
sanitize input to the 'searchWord', 'maxHits', 'scopedSearch', and
'scope' parameters of 'searchView.jsp' and the 'operation' parameter
of 'workingSet.jsp' before using it to generate dynamic HTML content. 
An unauthenticated, remote attacker may be able to leverage these
issues to inject arbitrary HTML or script code into a user's browser
to be executed within the security context of the affected site."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PK83895"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Please contact the vendor for a solution as a new help engine is
reportedly available to address these issues."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(79);
  script_set_attribute(
    attribute:"vuln_publication_date",
   value:"2009/10/15" 
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/10/15"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/20"
  );
 script_cvs_date("$Date: 2016/05/20 14:03:01 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:rational_requisitepro");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port =  get_http_port(default:80, no_xss: 1);

res = http_get_cache(item:"/", port:port, exit_on_fail: 1);

if("Rational Web Platform was installed and is running on this system" >!< res) 
  exit(0, "Rational RequisitePro is not running on port "+port+"." );

# Try couple of requests to exploit the flaw.
xss  = string(">''>","<script>alert('",SCRIPT_NAME,"')</script>");
xss2  = string("add*/--></script>","<script>alert('",SCRIPT_NAME,"')</script>");

exploit[0] = string("/ReqWebHelp/basic/searchView.jsp?searchWord=",xss);
 result[0] = string('"searchWord" value=',"'",xss);

exploit[1] = string("/ReqWebHelp/advanced/workingSet.jsp?operation=",xss2);
 result[1] = string('operation="+',"'",xss2);

for (i = 0 ; i < 2 ; i++)
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
    exit(0);
  }
}
exit(0, "The installed version of Rational RequisitePro on port "+port+" is not affected.");
