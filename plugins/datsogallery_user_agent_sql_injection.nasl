#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32317);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2017/05/19 13:58:06 $");

  script_cve_id("CVE-2008-5208");
  script_bugtraq_id(29138);
  script_osvdb_id(44969);
  script_xref(name:"EDB-ID", value:"5583");
  script_xref(name:"Secunia", value:"30139");

  script_name(english:"DatsoGallery Component for Joomla! sub_votepic.php User-Agent HTTP Header SQLi");
  script_summary(english:"Attempts to generate a SQL error.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the DatsoGallery component for Joomla! or Mambo
running on the remote host is affected by a SQL injection
vulnerability in sub_votepic.php due to improper sanitization of
user-supplied input to the User-Agent header before using it to
construct database queries. Regardless of the PHP 'magic_quotes_gpc'
setting, an unauthenticated, remote attacker can exploit this issue to
manipulate database queries, resulting in disclosure of sensitive
information, modification of data, or other attacks against the
underlying database.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("mambo_detect.nasl", "joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);
app = "Mambo / Joomla!";

# Generate a list of paths to check.
dirs = make_list();

# - Joomla
joomla_installs = get_installs(
  app_name : "Joomla!",
  port     : port
);

if (joomla_installs[0] == IF_OK)
{
  foreach install (joomla_installs[1])
  {
    dir = install['path'];
    dirs = make_list(dirs, dir);
  }
}

# - Mambo Open Source.
install = get_kb_item("www/"+port+"/mambo_mos");
if (install)
{
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches))
  {
    dir = matches[2];
    dirs = make_list(dirs, dir);
  }
}

if (max_index(dirs) == 0)
  audit(AUDIT_WEB_APP_NOT_INST, app, port);

magic = SCRIPT_NAME - ".nasl";
info = "";
non_affect = make_list();

# Loop through each directory.
foreach dir (dirs)
{
  # Try to exploit the issue to generate a SQL error.
  url = dir + "/components/com_datsogallery/sub_votepic.php?id=1&user_rating=1";

  r = http_send_recv3(
    method : "GET",
    item   : url,
    port   : port,
    add_headers  : make_array("User-Agent", magic+"'),nessus"),
    exit_on_fail : TRUE
  );

  # There's a problem if we see a SQL error involving the votes table.
  if (
    'datsogallery_votes ( vpic,' >< r[2] &&
    magic + "'),nessus'" >< r[2]
  )
  {
    vuln = TRUE;
    info += http_last_sent_request() + '|';
    output = strstr(r[2], magic);
    if (empty_or_null(output)) output = r[2];
  }
  non_affect = make_list(non_affect, dir);
  if (!thorough_tests) break;
}
if (vuln)
{
  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    line_limit  : 5,
    sqli        : TRUE,
    generic     : TRUE,
    request     : split(info, sep:"|", keep:FALSE),
    output      : chomp(output)
  );
  exit(0);
}

else
{
  installs = max_index(non_affect);

  if (installs == 1)
    audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:dir, port:port));

  else exit(0, "None of the "+app+" installs (" + join(non_affect, sep:" & ") + ") on port " + port + " are affected.");
}
