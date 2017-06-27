#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20112);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2005-3395");
  script_bugtraq_id(15240);
  script_osvdb_id(20419);

  script_name(english:"Invision Gallery index.php st Parameter SQL Injection");
  script_summary(english:"Checks for st parameter SQL injection vulnerability in Invision Gallery");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Invision Gallery, a community-based photo
gallery plugin for Invision Power Board. 

The version of Invision Gallery installed on the remote host fails to
properly sanitize user-supplied input to the 'st' parameter of the
'index.php' script before using it in database queries.  An attacker
may be able to leverage this issue to expose or modify sensitive data
or launch attacks against the underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/415297/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://forums.invisionpower.com/index.php?showtopic=197816" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor advisory above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/10/30");
 script_cvs_date("$Date: 2012/11/02 21:53:26 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:invision_power_services:invision_gallery");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/invision_power_board");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Exploitation requires a valid category.
  w = http_send_recv3(method:"GET", item:string(dir, "/?act=module&module=gallery"), port:port);
  if (isnull(w)) exit(1, "The web server did not answer");			  res = w[2];

  pat = "act=module&amp;module=gallery&amp;cmd=sc&amp;cat=([0-9]+)";
  matches = egrep(pattern:pat, string:res);
  foreach match (split(matches)) {
    match = chomp(match);
    cat = eregmatch(pattern:pat, string:match);
    if (!isnull(cat)) {
      cat = cat[1];
      break;
    }
  }


  # Try to exploit one of the SQL injection vulnerabilities.
  if (isnull(cat)) {
    debug_print("couldn't find a category to use!", level:1);
  }
  else {
    w = http_send_recv3(method:"GET",
      item:string(
        dir, "/index.php?",
        "act=module&",
        "module=gallery&",
        "cmd=sc&",
        "cat=", cat, "&",
        "sort_key=date&",
        "order_key=DESC&",
        "prune_key=30&",
        "st='", SCRIPT_NAME
      ),
      port:port
    );
    if (isnull(w)) exit(1, "The web server did not answer");
    res = w[2];

    # There's a problem if we see a SQL syntax error involving our script name.
    if (
      ("an error in your SQL syntax" >< res) &&
      (string("ORDER BY pinned DESC, date DESC , i.id DESC  LIMIT &amp;#39;", SCRIPT_NAME) >< res)
    ) {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
