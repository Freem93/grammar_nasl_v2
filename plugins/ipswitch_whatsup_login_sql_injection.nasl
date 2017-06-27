#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18552);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2012/07/20 18:51:35 $");

  script_cve_id("CVE-2005-1250");
  script_bugtraq_id(14039);
  script_osvdb_id(17450);

  script_name(english:"Ipswitch WhatsUp Professional Login.asp Multiple Field SQL Injection");
  script_summary(english:"Checks for SQL injection vulnerability in Ipswitch WhatsUp Professional's Login.asp");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is vulnerable to a
SQL injection attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Ipswitch WhatsUp Professional, a network
management and monitoring package. 

The web front-end for WhatsUp Professional on the remote host is prone
to a SQL injection attack because it fails to sanitize the 'sUserName'
and 'sPassword' parameters in the 'Login.asp' script.  An attacker may
be able to exploit this flaw to gain unauthenticated administrative
access to the affected application. 

Note that the web front-end is not installed as part of a default
configuration.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?775cfb0d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ipswitch WhatsUp Pro 2005 SP1a or disable its web
front-end.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/22");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ipswitch:whatsup");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);


# If the banner indicates it's for Ipswitch...
banner = get_http_banner(port:port);
if (banner && "Server: Ipswitch" >< banner) {
  # Try to exploit the flaw.
  postdata = string(
    "sUsername=", SCRIPT_NAME, "'&",
    "sPassword=nessus&",
    "btnLogin=Log+In&",
    "bIsJavaScriptDisabled=true"
  );
  w = http_send_recv3(method: "POST", port:port,
    item: "/NmConsole/Login.asp",
    content_type: "application/x-www-form-urlencoded",
    data: postdata );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if we see a syntax error.
  if (string("quotation mark before the character string '", SCRIPT_NAME, "''") >< res) {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
