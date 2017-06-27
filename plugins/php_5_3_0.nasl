#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58681);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/02 14:37:08 $");

  script_bugtraq_id(52065);
  script_osvdb_id(79763);

  script_name(english:"PHP 5.2.x filter_globals Subsequence Request Parsing Remote Code Execution");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that may be affected by a
remote code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP installed on the remote
host is in the 5.2 release branch.  As such, it reportedly may be
affected by a remote code execution vulnerability. 

An error in the file 'ext/filter/filter.c' does not properly clear the
'filter_globals' struct if PHP encounters issues during its start up
process.  This struct then contains stale values and can allow an
attacker to use a specially crafted request to crash PHP, obtain
sensitive information or possibly execute arbitrary code. 

Note that this issue reportedly only affects PHP when running as an
Apache module and not in other configurations such as CGI, nor when
used with other web servers such as IIS."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.3.0");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Feb/93");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=47930");
  script_set_attribute(attribute:"see_also", value:"http://svn.php.net/viewvc?view=revision&revision=279522");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.3.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "www/apache", "Settings/ParanoidReport");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");
include("webapp_func.inc");

# Make sure this is Apache.
get_kb_item_or_exit('www/'+port+'/apache');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port    = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

# All of 5.2.x is affected
if (version =~ "^5\.2([^0-9]|$)")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.3.0\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
