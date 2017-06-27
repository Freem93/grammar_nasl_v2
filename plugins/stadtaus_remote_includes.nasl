#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17285);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-0678");
  script_bugtraq_id(12735);
  script_osvdb_id(14572);

  script_name(english:"Stadtaus PHP Form Mail formmail.inc.php Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include flaw." );
 script_set_attribute(attribute:"description", value:
"There is a version of Form Mail Script, a PHP script by Ralf Stadtaus,
installed on the remote host that suffers from a remote file include
vulnerability involving the 'script_root' parameter of the
'inc/formmail.inc.php' script.  By leveraging this flaw, an attacker
may be able to view arbitrary files on the remote host or to execute
arbitrary PHP code, possibly taken from third-party hosts if PHP's
'register_globals' setting is enabled." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Mar/97" );
 script_set_attribute(attribute:"see_also", value:"http://www.stadtaus.com/forum/p-5887.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Form Mail Script version 2.4 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/07");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/04");
 script_cvs_date("$Date: 2016/11/03 20:40:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Detects file include vulnerabilities in Stadtaus' PHP Scripts";
  script_summary(english:summary["english"]);
 
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_category(ACT_ATTACK);
  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencies("http_version.nasl");
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


foreach dir (make_list(cgi_dirs())) {
  # Try to exploit the form to grab the mail template.
  w = http_send_recv3(method:"GET", item:string(dir, "/inc/formmail.inc.php?script_root=../templates/mail.tpl.txt%00"), port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # It's a problem if...
  if (
    # we get the template back or...
     'From: "{firstname} {lastname}" <{email}>' >< res  ||
    # magic_quotes_gpc=1 prevented us from opening the file.
    egrep(pattern:"<b>Warning</b>:  main\(\.\./templates/mail\.tpl\.txt\\0inc/functions\.inc\.php\)", string:res)
  ) {
    security_warning(port);
    exit(0);
  }
}
