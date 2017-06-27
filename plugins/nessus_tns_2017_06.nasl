#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99440);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/20 13:20:51 $");

  script_cve_id("CVE-2017-6543");
  script_bugtraq_id(96418);
  script_osvdb_id(152378);

  script_name(english:"Tenable Nessus 6.8.x < 6.10.2 Arbitrary File Upload (TNS-2017-06)");
  script_summary(english:"Checks the Nessus version.");

  script_set_attribute(attribute:"synopsis",value:
"An application running on the remote Windows host is affected by an
arbitrary file upload vulnerability.");
  script_set_attribute(attribute:"description",value:
"According to its self-reported version, the Tenable Nessus application
running on the remote host is 6.8.x, 6.9.x, or 6.10.x prior to 6.10.2.
It is, therefore, affected by an arbitrary file upload vulnerability
due to an unspecified flaw. An authenticated, remote attacker can
exploit this to upload a specially crafted file to an arbitrary system
location.");
  script_set_attribute(attribute:"see_also",value:"http://www.tenable.com/security/tns-2017-06");
  script_set_attribute(attribute:"solution",value:
"Upgrade to Tenable Nessus version 6.10.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/02/21");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/18");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("os_fingerprint.nasl", "nessus_detect.nasl");
  script_require_ports("Services/www", 8834);
  script_require_keys("Host/OS", "installed_sw/nessus");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

os = get_kb_item_or_exit("Host/OS");
if ('windows' >!< tolower(os))
  audit(AUDIT_OS_NOT, "Windows");

app = "nessus";
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:8834);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

version = install['version'];

fix = '6.10.2';

# Affected versions:
# 6.8.x, 6.9.x, 6.10.x < 6.10.2
if (version =~ '^(6\\.([89]|10)\\.)' && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  order = make_list('Installed version', 'Fixed version');
  report = make_array(
    order[0], version,
    order[1], fix
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Nessus", port, version);
