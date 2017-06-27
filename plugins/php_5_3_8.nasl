#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55969);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/16 14:22:05 $");

  script_cve_id("CVE-2011-3189");
  script_bugtraq_id(49376);
  script_osvdb_id(74726);
  script_xref(name:"Secunia", value:"45678");

  script_name(english:"PHP 5.3.7 crypt() MD5 Incorrect Return Value");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is affected by
a security bypass vulnerability."
  );
  
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, PHP 5.3.7 is installed on the
remote host.  This version contains a bug in the crypt()
function when generating salted MD5 hashes.  The function only
returns the salt rather than the salt and hash.  Any
authentication mechanism that uses crypt() could authorize all
authentication attempts due to this bug."
  );
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=55439");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/archive/2011.php#id2011-08-23-1");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP 5.3.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

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

# 5.3.7 was only around for a few days, it's unlikely that backporting will be a concern
#backported = get_kb_item('www/php/'+port+'/backported');
#if (report_paranoia < 2 && backported)
#  exit(1, "Security patches may have been backported.");

if (version =~ '^5(\\.3)?$') exit(1, "The banner for PHP on port "+port+" - "+source+" - is not granular enough to make a determination.");

if (version =~ "^5\.3\.7($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.3.8\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
