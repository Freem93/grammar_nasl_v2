#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20337);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2005-4567", "CVE-2005-4568", "CVE-2005-4569");
  script_bugtraq_id(15972);
  script_xref(name:"OSVDB", value:"22104");
  script_xref(name:"OSVDB", value:"22105");
  script_xref(name:"OSVDB", value:"22106");
  script_xref(name:"OSVDB", value:"22107");
  script_xref(name:"OSVDB", value:"22172");
  script_xref(name:"OSVDB", value:"22173");
  script_xref(name:"OSVDB", value:"22174");

  script_name(english:"FTGate <= 4.4.002 Multiple Remote Vulnerabilities (OF, FS, XSS)");
  script_summary(english:"Checks for multiple vulnerabilities in FTGate <= 4.4.002");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running a version of FTGate, a
commercial groupware mail server for Windows from FTGate Technology
Ltd. 

The web server used to administer FTGate on the remote host fails to
sanitize input to the 'href' parameter of the 'index.fts' script
before using it to generate dynamic content.  An unauthenticated
attacker can leverage this flaw to inject arbitrary HTML and script
code into a user's browser, to be evaluated within the security
context of the affected application. 

In addition, there reportedly is a buffer overflow vulnerability in
the web server as well as several format string vulnerabilities in the
accompanying IMAP and POP3 services.  An unauthenticated attacker may
be able to exploit these issues to execute code on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Dec/1038" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Dec/1040" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Dec/1041" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Dec/1042" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to FTGate version 4.4.004 or later as it reportedly fixes
these issues." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/20");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 8089);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:8089, embedded: 1);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# nb: the web server doesn't have a banner.

xss = '<script>alert("' + SCRIPT_NAME + '")</script>;';

# nb: FTGate apparently filters url-encode characters 
#     unless they're upper-case.
test_cgi_xss(port: port, cgi: "/item.fts", high_risk: 1,
  pass_str: string('NAME="href" VALUE="">', xss), 
  pass2_re: "TITLE>FTGate Web Admin",
  qs:  string("href=", urlencode(str:string('">', xss), case_type:HEX_UPPERCASE)));

