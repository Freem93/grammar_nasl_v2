#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(14770);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2004-0959");
  script_bugtraq_id(11190);
  script_osvdb_id(11148, 12603);
  script_xref(name:"RHSA", value:"2004:687");

  script_name(english:"PHP rfc1867.c $_FILES Array Crafted MIME Header Arbitrary File Upload");
  script_summary(english:"Checks for version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:"Arbitrary files may be uploaded on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of PHP that is older than 4.3.9 
or 5.0.2. 

The remote version of this software is affected by an unspecified file
upload vulnerability that could allow a local attacker to upload 
arbitrary files to the server.

** This flaw can only be exploited locally."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP 4.3.9 or 5.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/17");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

  script_dependencie("php_version.nasl");
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

if (version =~ "^4\.[0-2]\." ||
    version =~ "^4\.3\.[0-8]($|[^0-9])" ||
    version =~ "^5\.0\.[01]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 4.3.9 / 5.0.2\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
