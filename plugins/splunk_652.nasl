#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97100);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/07 15:11:00 $");

  script_cve_id(
    "CVE-2016-5418",
    "CVE-2016-8688",
    "CVE-2017-5607",
    "CVE-2017-5880"
  );
  script_bugtraq_id(
    93165,
    93781,
    95804,
    97265,
    97286
  );
  script_osvdb_id(
    142328,
    142329,
    142330,
    142331,
    143142,
    144730,
    151051,
    152526,
    154700,
    154701
  );

  script_name(english:"Splunk Enterprise < 5.0.17 / 6.0.13 / 6.1.12 / 6.2.13 / 6.3.9 / 6.4.5 / 6.5.2 or Splunk Light < 6.5.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Splunk Enterprise and Light.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Splunk
Enterprise hosted on the remote web server is 5.0.x prior to 5.0.17,
6.0.x prior to 6.0.13, 6.1.x prior to 6.1.12, 6.2.x prior to 6.2.13,
6.3.x prior to 6.3.9, 6.4.x prior to 6.4.5, or 6.5.x prior to 6.5.2;
or else it is Splunk Light prior to 6.5.2. It is, therefore, affected
by multiple vulnerabilities :

  - A security bypass vulnerability exists in the libarchive
    component due to a failure to properly check hardlinks
    that contain payload data. An unauthenticated, remote
    attacker can exploit this to bypass sandbox
    restrictions. (CVE-2016-5418)

  - An out-of-bounds write error exists in the libarchive
    component in the get_line_size() function in
    archive_read_support_format_mtree.c that is triggered
    when parsing lines. An unauthenticated, remote attacker
    can exploit this to crash the library or disclose
    memory contents. (CVE-2016-8688)

 -  An information disclosure vulnerability exists in Splunk
    Light due to various system information being assigned
    to the global window property '$C' when a request is
    made to '/en-US/config?autoload=1'. An unauthenticated,
    remote attacker attacker can exploit this, via a
    specially crafted web page, to disclose sensitive
    information. (CVE-2017-5607)

  - A denial of service vulnerability exists in the Splunk
    Web component due to improper validation of
    user-supplied input. An authenticated, remote attacker
    can exploit this, via a specially crafted GET request,
    to crash the daemon. (CVE-2017-5880)

  - A flaw exists in the libarchive component in the
    check_symlinks() function in archive_write_disk_posix.c
    that is triggered during the handling of subdirectories.
    An unauthenticated, remote attacker can exploit this to
    overwrite arbitrary files. (VulnDB 142328)

  - A flaw exists in the libarchive component in the
    edit_deep_directories() function due to symlink checks
    and deep-directory support failing to properly handle
    overly long pathnames. An unauthenticated, remote
    attacker can exploit this to overwrite arbitrary files.
    (VulnDB 142329)

  - A flaw exists in the libarchive component in the
    check_symlinks() function that is due to an overly
    aggressive cached path handling mechanism. An
    unauthenticated, remote attacker can exploit this to
    make changes to the permissions of arbitrary
    directories. (VulnDB 142330)

  - An out-of-bounds write error exists in the libarchive
    component in the bsdtar_expand_char() function in util.c
    due to improper handling of crafted archives. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to open or load a specially crafted
    archive, to execute arbitrary code. (VulnDB 143142)

  - A stored cross-site scripting (XSS) vulnerability exists
    due to improper validation of input before returning it
    to users. An authenticated, remote attacker who has
    administrative access can exploit this, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (VulnDB 152526)

  - A stored cross-site scripting (XSS) vulnerability exists
    in Splunk Light within the web interface due to improper
    validation of unspecified input before returning to
    users. An authenticated, remote attacker can exploit
    this, via a specially crafted request, to execute
    arbitrary script code in a user's browser session.
    (VulnDB 154701)

Note that the vulnerabilities in the libarchive component do not
affect Splunk Enterprise 6.5.1 or Splunk Light 6.5.1.");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/view/SP-CAAAPW8");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/view/SP-CAAAPYC");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/view/SP-CAAAPZ3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Splunk Enterprise version 5.0.17 / 6.0.13 / 6.1.12 /
6.2.13 / 6.3.9 / 6.4.5 / 6.5.2 or later. Upgrade Splunk Light to
version 6.5.2 or later.

Note that for Splunk Enterprise 6.4.x, the fix for VulnDB 152526
requires an upgrade to version 6.4.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl");
  script_require_ports("Services/www", 8089, 8000);
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Splunk";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8000, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];
license = install['License'];
if (isnull(license)) exit(1, "Unable to retrieve the Splunk license type.");

fix = FALSE;

install_url = build_url(qs:dir, port:port);

if (license == "Enterprise")
{
  # 5.0.x < 5.0.17
  if (ver =~ "^5\.0($|[^0-9])")
    fix = '5.0.17';

  # 6.0.x < 6.0.13
  else if (ver =~ "^6\.0($|[^0-9])")
    fix = '6.0.13';

  # 6.1.x < 6.1.12
  else if (ver =~ "^6\.1($|[^0-9])")
    fix = '6.1.12';

  # 6.2.x < 6.2.13
  else if (ver =~ "^6\.2($|[^0-9])")
    fix = '6.2.13';

  # 6.3.x < 6.3.9
  else if (ver =~ "^6\.3($|[^0-9])")
    fix = '6.3.9';

  # 6.4.x < 6.4.5
  else if (ver =~ "^6\.4($|[^0-9])")
    fix = '6.4.5';

  # 6.5.x < 6.5.2
  else if (ver =~ "^6\.5($|[^0-9])")
    fix = '6.5.2';
}
else if (license == "Light")
{
  # any < 6.5.2
  fix = '6.5.2';
}

if (fix && ver_compare(ver:ver,fix:fix,strict:FALSE) < 0)
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_url,
    order[1], ver + " " + license,
    order[2], fix + " " + license
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE, xss:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver + " " + license);
