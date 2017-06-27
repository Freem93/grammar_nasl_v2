#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92465);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/03/03 17:07:25 $");

  script_cve_id(
    "CVE-2016-0718",
    "CVE-2016-1000028",
    "CVE-2016-1000029"
  );
  script_bugtraq_id(90729);
  script_osvdb_id(138680);

  script_name(english:"Tenable Nessus 6.x < 6.8 Multiple Vulnerabilities");
  script_summary(english:"Checks the Nessus version.");

  script_set_attribute(attribute:"synopsis",value:
"An application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"According to its self-reported version number, the Tenable Nessus
application running on the remote host is 6.x prior to 6.8. It is,
therefore, affected by multiple vulnerabilities :

  - A buffer overflow condition exists in the Expat XML
    parser due to improper validation of user-supplied input
    when handling malformed input documents. An
    authenticated, remote attacker can exploit this to cause
    a denial of service condition or the execution of
    arbitrary code. (CVE-2016-0718)

  - A stored cross-site (XSS) scripting vulnerability exists
    that can be exploited by an authenticated, remote
    attacker that has user-level access to the Nessus user
    interface. (CVE-2016-1000028)

  - Multiple stored cross-site (XSS) scripting
    vulnerabilities exist that can be exploited by an
    authenticated, remote attacker that has
    administrative-level access to the Nessus user
    interface. These issues would only affect other users
    with administrative access. (CVE-2016-1000029)");
  script_set_attribute(attribute:"see_also",value:"https://www.tenable.com/security/tns-2016-11");
  script_set_attribute(attribute:"solution",value:
"Upgrade to Tenable Nessus version 6.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/05/17");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/20");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libexpat:expat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("nessus_detect.nasl");
  script_require_ports("Services/www", 8834);
  script_require_keys("installed_sw/nessus");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

app = "nessus";
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:8834);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

version = install['version'];

fix = '6.8';

# Affected versions:
# 6.x < 6.8
if (version =~ '^6\\.' && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  order = make_list('Installed version', 'Fixed version');
  report = make_array(
    order[0], version,
    order[1], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE, xss:TRUE);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Nessus", port, version);
