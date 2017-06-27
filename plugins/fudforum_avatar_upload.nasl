#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19520);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-2781");
  script_bugtraq_id(14678);
  script_osvdb_id(18953);

  script_name(english:"FUDforum < 2.7.1 Avatar Upload Extension Validation Weakness Arbitrary Code Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that allows for
arbitrary code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running FUDforum, an open source web forum written
in PHP. 

According to its banner, the version of FUDforum installed on the
remote host may allow an authenticated attacker to upload a file with
arbitrary PHP code as an avatar image and later run that code subject
to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Aug/392" );
 script_set_attribute(attribute:"see_also", value:"http://fudforum.org/forum/index.php?t=msg&th=5470&start=0&" );
 script_set_attribute(attribute:"solution", value:
"Upload to FUDforum 2.7.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/29");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/23");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:ilia_alshanetsky:fudforum");
script_end_attributes();

  script_summary(english:"Checks for avatar upload vulnerability in FUDforum < 2.7.1");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, php: 1);

# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Request the main index.php script.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  if (egrep(string:res, pattern:'>Powered by: FUDforum ([01]\\.|2.([0-6]\\.|7\\.0)).+&copy;.+ <a href="http://fudforum.org/">')) {
    security_warning(port);
    exit(0);
  }
}

