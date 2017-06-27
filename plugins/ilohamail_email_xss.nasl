#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18050);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2005-1120");
  script_bugtraq_id(13175);
  script_osvdb_id(15506);

  script_name(english:"IlohaMail read_message.php Attachment Multiple Field XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is subject to
cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"Based on its version number, the installation of IlohaMail on the
remote host does not properly sanitize attachment file names, MIME
media types, and HTML / text email messages.  An attacker can exploit
these vulnerabilities by sending a specially crafted message to a user
which, when read using an affected version of IlohaMail, will allow
the attacker to execute arbitrary HTML and script code in the user's browser
within the context of the affected website." );
 script_set_attribute(attribute:"see_also", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=304525" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IlohaMail version 0.8.14-rc3 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/14");
 script_cvs_date("$Date: 2015/01/14 03:46:10 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for email message cross-site scripting vulnerabilities in IlohaMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("ilohamail_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/ilohamail"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];
  # nb: versions 0.8.14-rc2 and earlier may be affected.
  if (ver =~ "^0\.([1-7].*|8\.([0-9]([^0-9]|$)|1([0-3]|4.*rc[12])))")
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
