#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(50418);
 script_version("$Revision: 1.6 $");
 script_cvs_date("$Date: 2014/12/30 18:54:52 $");

 script_name(english: "CGI Generic Fragile Parameters Detection (potential)");

 # 717 OWASP Top Ten 2007 Category A6 - Information Leakage and Improper Error Handling
 # 728 OWASP Top Ten 2004 Category A7 - Improper Error Handling
 # 203 Information Exposure Through Discrepancy
 # 205 Information Exposure Through Behavioral Discrepancy

 script_set_attribute(attribute:"synopsis", value:
"A web application returns 500 codes." );
 script_set_attribute(attribute:"description", value:
"A web application hosted on the remote service returned 50x response
codes when discovered CGIs were called with invalid values.  These
codes may have several origins :

  - A web application firewall or another defense mechanism 
    may abruptly interrupt the request.

  - There could be a transient web server or back-end 
    failure. Common codes in such cases are 503 'Service
    Unavailable' or 504 'Gateway Timeout'.

  - A processing error resulted in the crash of the CGI or 
    a back-end module. Codes like 500 'Internal Server 
    Error' or 502 'Bad Gateway' may be seen in such cases. 

501 'Not Implemented' or 505 'HTTP Version Not Supported' codes should
be seen during Nessus tests. 

The reported CGIs should be audited." );

 script_set_attribute(attribute:"solution", value:
"  - Audit the relevant CGIs.

  - Filter out malformed input data.

  - Trap processing errors." );
 script_set_attribute(attribute:"risk_factor", value: "Low" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/30");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Look for 50x HTTP codes.");
 script_category(ACT_END);

 script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl", "web_app_test_settings.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/enable_web_app_tests", "Settings/HTTP/OWASP10");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi.inc");


####

codes = make_array(
 500,	"Internal Server Error",
 501,	"Not Implemented",
 502,	"Bad Gateway",
 503,	"Service Unavailable",
 504,	"Gateway Timeout",
 505,	"HTTP Version Not Supported" );

port = torture_cgi_init();

report = "";
n = 0;
for (code = 500; code <= 509; code ++) 
{
  cgi_l = get_kb_list("www/"+port+"/code/"+code+"/cgi");
  if (isnull(cgi_l)) continue;

  txt = '';
  foreach cgi (make_list(cgi_l))
  {
    n ++;
    param_l = get_kb_list("www/"+port+"/code/"+code+"/cgi-arg"+cgi);
    if (isnull(param_l))
    {
      err_print("No vulnerable argument on port ", port, " for CGI ", cgi, " (code=", code, ").");
      continue;
    }
    txt = strcat(txt, '  CGI : ', cgi, '\n');
    foreach param (make_list(param_l))
      txt = strcat(txt, '  Parameter : ', param, '\n');
    txt += '\n';
  }
  if (txt)
  {
    report = strcat(report, '\nCode ', code); 
    if (codes[code]) report = strcat(report, ' (', codes[code], ') ');
    report = strcat(report, ' was received when testing these CGIs :\n\n', txt, '\n');
  }
}

if (strlen(report) > 0)
{
  report = '\nHere is the list of potentially fragile CGIs / parameters :\n'+ report;
  security_note(port:port, extra: report);
  exit(0);
}
else if (n == 0)
  exit(0, "No 50x code was received from port "+port+".");
else
  exit(1, "Inconsistent data in KB (port="+port+").");

