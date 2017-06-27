#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18354);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-1714");
  script_bugtraq_id(13689);
  script_osvdb_id(16690);

  script_name(english:"SurgeMail <= 3.0c2 Multiple XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is vulnerable to multiple cross-site scripting
attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running SurgeMail version
3.0c2 or earlier.  These versions reportedly are prone to multiple
cross-site scripting issues, which an attacker could exploit to inject
arbitrary HTML and script code into a user's browser to be processed
within the context of the affected website." );
 script_set_attribute(attribute:"see_also", value:"http://www.netwinsite.com/surgemail/help/updates.htm" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SurgeMail 3.2e1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/19");
 script_cvs_date("$Date: 2015/01/23 22:03:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in SurgeMail <= 3.0c2";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25, "Services/www", 7080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("smtp_func.inc");


# Make sure the banner indicates it's from SurgeMail.
port = get_http_port(default:7080, embedded: 1);
banner = get_http_banner(port:port);
if (!banner) exit(1, "No web banner on port "+port);
if ("DManager" >!< banner) exit(0, "The web server on port "+port+" is not DManager");


# Unfortunately, the web server doesn't include its version in the 
# Server response header so let's pull it from the SMTP server.
smtpport = get_kb_item("Services/smtp");
if (!smtpport) smtpport = 25;
if (! get_port_state(smtpport)) exit(0, "Port "+smtpport+" is closed");
banner = get_smtp_banner(port:smtpport);
if (banner) {
  ver = ereg_replace(
    string:banner, 
    pattern:"^[0-9][0-9][0-9] .* SurgeSMTP \(Version ([^)]+).+",
    replace:"\1"
  );

  # There's a problem if it's 3.0c2 or earlier.
  if (ver && ver =~ "^([0-2]\.|3\.0([ab]|c([0-2]|$)))") 
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
