#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18288);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2005-0927");
  script_bugtraq_id(12938);
  script_osvdb_id(15105);

  script_name(english:"web-app.org WebAPP Encoded Request .dat File Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
WebAPP that suffers from an unspecified file disclosure vulnerability. 
An attacker may be able to use this flaw to disclose the contents of
'dat' files." );
 script_set_attribute(attribute:"see_also", value:"http://www.web-app.org/cgi-bin/index.cgi?action=viewnews&id=195" );
 script_set_attribute(attribute:"solution", value:
"Apply the March 2005 Security Update." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/28");
 script_cvs_date("$Date: 2011/03/15 19:26:57 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for file disclosure vulnerability in WebAPP");
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

  script_family(english:"CGI abuses");

  script_dependencies("webapp_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Test an install.
install = get_kb_item(string("www/", port, "/webapp"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: versions below 0.9.9.2.1 are vulnerable.
  if (ver =~ "^0\.([0-8]([^0-9]|$)|9([^0-9.]|$|\.[0-8]([^0-9]|$)|\.9([^0-9.]|$|\.[01]([^0-9]|$)|\.2([^0-9.]|$|\.1[^0-9]))))")
    security_warning(port);
}
