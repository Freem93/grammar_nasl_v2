#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(18568);
  script_version("$Revision: 1.18 $");
  script_cve_id("CVE-2005-2047", "CVE-2006-6365");
  script_bugtraq_id(14034);
  script_osvdb_id(17596, 17600, 17601, 17602, 35836);

  script_name(english:"DUpaypal Pro Multiple Scripts SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is vulnerable
to multiple SQL injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running DUpaypal Pro, an ASP-based storefront from
DUware for Paypal. 

The installed version of DUpaypal Pro fails to properly sanitize user-
supplied input in several instances before using it in SQL queries. 
By exploiting these flaws, an attacker can affect database queries,
possibly disclosing sensitive data and launching attacks against the
underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://echo.or.id/adv/adv19-theday-2005.txt" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jun/175" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/22");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for multiple SQL injection vulnerabilities in DUpaypal Pro");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the flaws.
  u = string(
      dir, "/shops/sub.asp?",
      "iSub=", SCRIPT_NAME, "'"
    );
  r = http_send_recv3(method: "GET", port:port, item: u);
  if (isnull(r)) exit(0);

  # There's a problem if...
  if (
    # it looks like DUpaypal Pro and...
    'href="../css/DUpaypalPro.css" rel="stylesheet" ' >< r[2] && 
    # there's a syntax error.
    egrep(string:r[2], pattern:string("Syntax error .+ AND PRO_SUBS.SUB_ID = ", SCRIPT_NAME, "'"))
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
