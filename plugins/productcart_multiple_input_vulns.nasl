#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(17971);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_cve_id("CVE-2005-0994", "CVE-2005-0995");
  script_bugtraq_id(12990);
  script_osvdb_id(15263, 15264, 15266, 15268);

  script_name(english:"ProductCart Multiple Input Validation Vulnerabilities");
  script_summary(english:"Checks for multiple input validation vulnerabilities in ProductCart");
 
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is affected by
several flaws.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the ProductCart shopping cart
software that suffers from several input validation vulnerabilities:

  - SQL Injection Vulnerabilities
    The 'advSearch_h.asp' script fails to sanitize user input to
    the 'idCategory', and 'resultCnt' parameters, allowing an
    attacker to manipulate SQL queries.

  - Multiple Cross-Site Scripting Vulnerabilities
    The application fails to sanitize user input via the 
    'redirectUrl' parameter of the 'NewCust.asp' script, the
    'country' parameter of the 'storelocator_submit.asp' script,
    the 'error' parameter of the 'techErr.asp' script, and the 
    'keyword' parameter of the 'advSearch_h.asp' script before
    using it in dynamically-generated web content. An attacker
    can exploit these flaws to cause arbitrary HTML and script
    code to be executed in a user's browser in the context of 
    the affected website.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, asp:TRUE);


# Check various directories for ProductCart.
foreach dir (cgi_dirs())
{
  # Try to pull up ProductCart's search page.
  r = http_send_recv3(method:"GET", item:string(dir, "/advSearch_h.asp"), port:port, exit_on_fail:TRUE);

  # If it's ProductCart, we should see an error message like:
  #   <font face="Arial" size=2>/productcart/pc/advSearch_h.asp</font><font face="Arial" size=2>, line 161</font>
  if (
    "/advSearch_h.asp<" >< r[2] &&
    ", line <" >< r[2] &&
    egrep(string:r[2], pattern:">" + dir + "/advSearch_h\.asp<.+, line [0-9]+</font>")
  )
  {
    # Try the exploit.
    r = http_send_recv3(method:"GET",
      item:string(
        dir, "/advSearch_h.asp?",
        "priceFrom=0&",
        "priceUntil=999999999&",
        # nb: this should just cause a syntax error.
        "idCategory='", SCRIPT_NAME, "&",
        "idSupplier=10&",
        "resultCnt=10&",
        "keyword=Nessus"
      ), 
      port:port,
      exit_on_fail:TRUE
    );

    # If we get a syntax error in the query, there's a problem.
    if (string("Syntax error in string in query expression 'idCategory='", SCRIPT_NAME, "'") >< r[2]) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
