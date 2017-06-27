#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Wed, 15 Dec 2004 19:46:20 +0100
#  From: Stefan Esser <sesser@php.net>
#  To: bugtraq@securityfocus.com, full-disclosure@lists.netsys.com
#  Subject: Advisory 01/2004: Multiple vulnerabilities in PHP 4/5  
#


include("compat.inc");

if(description)
{
  script_id(15973);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/06/24 14:42:21 $");

  script_cve_id(
    "CVE-2004-1018", 
    "CVE-2004-1019", 
    "CVE-2004-1020", 
    "CVE-2004-1063", 
    "CVE-2004-1064", 
    "CVE-2004-1065"
  );
  script_bugtraq_id(
    11964, 
    11981, 
    11992, 
    12045
  );
  script_osvdb_id(
    12410,
    12411,
    12412,
    12413,
    12415,
    12600,
    12602,
    34717
  );

  script_name(english:"PHP < 4.3.10 / 5.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks for version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is potentially
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is prior to 4.3.10 / 5.0.3.  It is, therefore, affected by
multiple security issues that could, under certain circumstances,
allow an attacker to execute arbitrary code on the remote host,
provided that the attacker can pass arbitrary data to some
functions, or to bypass safe_mode."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.0.3" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 5.0.3 or 4.3.10." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2004/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/15");
  
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

if (version =~ "^4\.[012]\." ||
    version =~ "^4\.3\.[0-9]($|[^0-9])" ||
    version =~ "^5\.0\.[012]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 4.3.10 / 5.0.3\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
