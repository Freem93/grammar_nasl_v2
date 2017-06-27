#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17301);
  script_version("$Revision: 1.22 $");

  script_cve_id("CVE-2005-0659", "CVE-2005-0673", "CVE-2005-1026");
  script_bugtraq_id(12736, 13028, 13030);
  script_osvdb_id(
    14368, 
    14571, 
    15483, 
    15484
 );

  script_name(english:"phpBB <= 2.0.13 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of phpBB
that suffers from multiple flaws:

  - A Path Disclosure Vulnerability
    A remote attacker can cause phpBB to reveal its installation
    path via a direct request to the script 'db/oracle.php'.

  - A Cross-Site Scripting Vulnerability
    The application does not properly sanitize user input before
    using it in 'privmsg.php' and 'viewtopic.php'.

  - A Privilege Escalation Vulnerability
    In 'session.php' phpBB resets the 'user_id' value when an 
    autologin fails; it does not, however, reset the 'user_level' 
    value, which remains as the account that failed the autologin.
    Since the software uses the 'user_level' parameter in some 
    cases to control access to privileged functionality, this flaw
    allows an attacker to view information, and possibly even 
    perform tasks, normally limited to administrators. 

  - SQL Injection Vulnerabilities
    The DLMan Pro and LinksLinks Pro mods, if installed, reportedly 
    fail to properly sanitize user input to the 'file_id' parameter
    of the 'dlman.php' script and the 'id' parameter of the
    'links.php' script respectively before using it in a SQL 
    query. This may allow an attacker to pass malicious input
    to database queries." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Mar/99" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Mar/113" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Apr/62" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Apr/69" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a version after phpBB 2.0.13 and disable the DLMan Pro and
LinksLinks Pro mods." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/03");
 script_cvs_date("$Date: 2016/11/02 14:37:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpbb_group:phpbb");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in phpBB 2.0.13 and older";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("phpbb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpBB");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^([01]\..*|2\.0\.([0-9]|1[0-3])([^0-9]|$))") 
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
