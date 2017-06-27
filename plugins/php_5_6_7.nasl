#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82027);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/20 14:30:35 $");

  script_cve_id(
    "CVE-2015-0231",
    "CVE-2015-2305",
    "CVE-2015-2331",
    "CVE-2015-2348",
    "CVE-2015-2787"
  );
  script_bugtraq_id(
    72539,
    73182, 
    73381,
    73383,
    73385,
    73431,
    73434
  );
  script_osvdb_id(
    116020,
    118433,
    119693,
    119773,
    119774
  );

  script_name(english:"PHP 5.6.x < 5.6.7 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.6.x installed on the
remote host is prior to 5.6.7. It is, therefore, affected by multiple
vulnerabilities :

  - A use-after-free error exists related to function
    'unserialize', which can allow a remote attacker to
    execute arbitrary code. Note that this issue is due to
    an incomplete fix for CVE-2014-8142. (CVE-2015-0231)

  - An integer overflow error exists in function 'regcomp'
    in the Henry Spencer regex library, due to improper
    validation of user-supplied input. An attacker can
    exploit this to cause a denial of service or to execute
    arbitrary code. (CVE-2015-2305)

  - An integer overflow error exists in the '_zip_cdir_new'
    function, due to improper validation of user-supplied
    input. An attacker, using a crafted ZIP archive, can
    exploit this to cause a denial of service or to execute
    arbitrary code. (CVE-2015-2331)

  - A filter bypass vulnerability exists due to a flaw in
    the move_uploaded_file() function in which pathnames are
    truncated when a NULL byte is encountered. This allows a
    remote attacker, via a crafted second argument, to
    bypass intended extension restrictions and create files
    with unexpected names. (CVE-2015-2348)

  - A user-after-free error exists in the
    process_nested_data() function. This allows a remote
    attacker, via a crafted unserialize call, to dereference
    already freed memory, resulting in the execution of
    arbitrary code. (CVE-2015-2787)

Note that Nessus has not attempted to exploit these issues but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.7");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=69207");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=68976");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.6.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.6)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.6\.") audit(AUDIT_NOT_DETECT, "PHP version 5.6.x", port);

if (version =~ "^5\.6\.[0-6]($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version +
      '\n  Fixed version     : 5.6.7' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
