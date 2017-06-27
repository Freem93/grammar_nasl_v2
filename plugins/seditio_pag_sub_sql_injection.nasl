#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28375);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2007-6202");
  script_bugtraq_id(26655);
  script_osvdb_id(38924);
  script_xref(name:"EDB-ID", value:"4678");

  script_name(english:"Seditio plug.php pag_sub Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The version of Seditio installed on the remote host fails to sanitize
user input to the 'pag_sub' parameter of the '/plug.php' script when
used in conjunction with the search action before using it in a
database query.  Provided PHP's 'magic_quotes_gpc' setting is
disabled, an attacker may be able to exploit this issue to manipulate
database queries, leading to disclosure of sensitive information,
modification of data, or attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.neocrome.net/page.php?id=2349" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Seditio version 121 released on 2007-11-30 or later. 

Note that the authors have released an update that addresses this
issue without changing the version number.  Verify that 'Updated' in
the comment at the top of '/plugins/search/search.php' is
'2007-nov-30' or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/11/29");
 script_cvs_date("$Date: 2011/03/12 01:05:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  script_dependencies("seditio_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/seditio");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/seditio"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Make sure the affected script and functionality exist.
  url = string(dir, "/plug.php?e=search");

  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # If so...
  if ('action="plug.php?e=search&amp;a=search" method="post"' >< res)
  {
    # Try to exploit the issue to generate a SQL error.
    exploit = string("qwerty')", SCRIPT_NAME);

    postdata = string(
      "sq=nessus&",
      "frm_sub[]=9999&",
      "sea_frmtitle=1&",
      "sea_frmtext=1&",
      "sea_pagtitle=1&",
      "sea_pagdesc=1&",
      "sea_pagtext=1&",
      "searchin_pag=1&",
      "pag_sub[]=", exploit, "&",
      "x=GUEST"
    );
    w = http_send_recv3(method:"POST", port: port, item: strcat(url, "&a=search"),
      content_type: "application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
    res = w[2];

    # There's a problem if we see an error message with our script name.
    if (string("right syntax to use near '", SCRIPT_NAME, "') ORDER by") >< res)
    {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
