#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63639);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/16 19:35:39 $");

  script_cve_id("CVE-2012-5565");
  script_bugtraq_id(56666);
  script_osvdb_id(87346, 105422);

  script_name(english:"Horde IMP js/compose-dimp.js XSS");
  script_summary(english:"Checks compose-dimp.js for vulnerable code");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP application that is affected by a
cross-site scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of IMP (Internet Mail Program) installed on the remote host
is affected by a cross-site scripting vulnerability because it fails to
properly sanitize user-supplied input when a user uploads an attachment. 
An attacker can use a specially crafted request to inject arbitrary HTML
and script code into a user's browser to be executed within the security
context of the affected site. 

Note that Horde Groupware Webmail Edition is also affected as this
bundle includes IMP."
  );
  script_set_attribute(attribute:"see_also", value:"https://lists.horde.org/archives/announce/2012/000833.html");
  script_set_attribute(attribute:"see_also", value:"https://lists.horde.org/archives/announce/2012/000840.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to IMP H4 5.0.24 / Groupware Webmail Edition 4.0.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:imp");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("imp_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/imp", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(
  appname      : "imp",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(port:port, qs:dir);

url = "/js/compose-dimp.js";
res = http_send_recv3(
  method       : "GET",
  item         : dir + url,
  port         : port,
  exit_on_fail : TRUE
);

vuln = FALSE;

if ("var DimpCompose" >< res[2])
{
  line = "\$\('upload_wait'\)\.update\(DimpCore\.text\.uploading \+ ' \(' \+ \$F\(u\) \+ '\)'\)\.show\(\);";

  patch = ".escapeHTML()";
  output = egrep(pattern:line, string:res[2]);

  if (output && patch >!< output) vuln = TRUE;
}

if (!vuln) audit(AUDIT_WEB_APP_NOT_AFFECTED, "IMP", install_url + "/");

set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to verify the issue by examining the source of' +
    '\n' + url + ' using the following URL : ' +
    '\n' +
    '\n  ' + install_url + url +
    '\n';

  if (report_verbosity > 1)
  {
    snip = crap(data:"-", length:30) +" snip "+ crap(data:"-", length:30) +'\n';
    report +=
      '\nNessus determined the following vulnerable code sequence has not' +
      '\nbeen remedied in this version of IMP : ' +
      '\n' +
      '\n' + snip + chomp(output) +
      '\n' + snip +
      '\n';
  }
  security_warning(port:port, extra:report);
}
else security_warning(port);
