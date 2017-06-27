#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# Date: Tue, 25 Mar 2003 14:31:59 +0000
# From: Sir Mordred <mordred@s-mail.com>
# To: bugtraq@securityfocus.com
# Subject: @(#)Mordred Labs advisory - Integer overflow in PHP socket_iovec_alloc() function



include("compat.inc");

if(description)
{
  script_id(11468);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2013/10/23 20:09:34 $");

  script_cve_id("CVE-2003-0166");
  script_bugtraq_id(
    7187, 
    7197, 
    7198, 
    7199, 
    7256, 
    7259
  );
  script_osvdb_id(
    13393,
    13394,
    13395,
    13396
  );

  script_name(english:"PHP socket_iovec_alloc() Function Overflow");
  script_summary(english:"Checks for version of PHP");
 
  script_set_attribute(
    attribute:"synopsis",
    value:"Arbitrary code may be run on the remote server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of PHP that is older than 4.3.2.

There is a flaw in this version that could allow an attacker who has the 
ability to inject an arbitrary argument to the function 
socket_iovec_alloc() to crash the remote service and possibly to execute 
arbitrary code.

For this attack to work, PHP has to be compiled with the option
--enable-sockets (which is disabled by default), and an attacker needs 
to be able to pass arbitrary values to socket_iovec_alloc().

Other functions are vulnerable to such flaws : openlog(), socket_recv(), 
socket_recvfrom() and emalloc()"
  );
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 4.3.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");

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

if (version =~ "^[1-3]\." ||
    version =~ "^4\.[0-2]\." ||
    version =~ "^4\.3\.[0-1]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 4.3.2\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
