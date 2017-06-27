#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99932);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/04 13:21:26 $");

  script_cve_id("CVE-2015-8357");
  script_bugtraq_id(79776);
  script_osvdb_id(130821);
  script_xref(name:"EDB-ID", value:"38976");
  script_xref(name:"IAVA", value:"2017-A-0129");

  script_name(english:"Bitrix bitrix.xscan Module < 1.0.4 bitrix.xscan_worker.php 'file' Parameter Path Traversal File Disclosure");
  script_summary(english:"Checks the version of bitrix.xscan module.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server contains a module
that is affected by a path traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Bitrix bitrix.xscan module running on the remote
web server is prior to 1.0.4. It is, therefore, affected by a path
traversal vulnerability due to a failure to properly sanitize
user-supplied input to the 'file' parameter passed to the
/bitrix/admin/bitrix.xscan_worker.php script. An authenticated, remote
attacker can exploit this, via a specially crafted HTTP GET request,
to rename arbitrary files and read the content of arbitrary files on
the host.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported module version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.htbridge.com/advisory/HTB23278");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Bitrix bitrix.xscan module version 1.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:bitrix:bitrix");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bitrix:xscan");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("bitrix_detect.nbin");
  script_require_keys("www/PHP", "installed_sw/Bitrix");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

app = "bitrix.xscan for Bitrix";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443, php:TRUE);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:2);
constraints = [{"fixed_version" : "1.0.4"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
