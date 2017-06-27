#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91131);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/15 04:43:20 $");

  script_cve_id(
    "CVE-2016-0900",
    "CVE-2016-0901",
    "CVE-2016-0902"
  );
  script_bugtraq_id(
    90167,
    90168,
    90169
  );
  script_osvdb_id(
    138090,
    138091,
    138092
  );
  script_xref(name:"IAVB", value:"2016-B-0085");

  script_name(english:"EMC RSA Authentication Manager < 8.1 SP1 Patch 14 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of EMC RSA Authentication Manager.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of EMC RSA Authentication Manager running on the remote
host is prior to 8.1 SP1 Patch 14. It is, therefore, affected by
multiple vulnerabilities :

  - Multiple cross-site scripting vulnerabilities exist due
    to a failure to properly validate input before returning
    it to users. An unauthenticated, remote attacker can
    exploit these, via a specially crafted request, to
    execute arbitrary HTML or script code in the user's
    browser session. (CVE-2016-0900, CVE-2016-0901)

  - A flaw exists due to a failure to properly sanitize
    carriage return and line feed (CRLF) character sequences
    in HTTP responses headers. An unauthenticated, remote
    attacker can exploit this to inject arbitrary HTTP
    headers and to conduct HTTP response splitting attacks.
    (CVE-2016-0902)");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2016/May/att-23/ESA-2016-051.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC RSA Authentication Manager version 8.1 SP1 Patch 14 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_authentication_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:authentication_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("emc_rsa_am_detect.nbin");
  script_require_keys("www/emc_rsa_am");
  script_require_ports("Services/www", 7004);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

get_kb_item_or_exit("www/emc_rsa_am");

app_name = "EMC RSA Authentication Manager";
port = get_http_port(default:7004);
kb_prefix = "www/"+port+"/emc_rsa_am/";

report_url = get_kb_item_or_exit(kb_prefix + "url");
version = get_kb_item_or_exit(kb_prefix + "version");
version_display = get_kb_item_or_exit(kb_prefix + "version_display");

fix = '8.1.1.14';
fix_display = "8.1 SP1 Patch 14";

if (version =~ "^[0-8]\." && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  URL               : ' + report_url +
    '\n  Installed version : ' + version_display +
    '\n  Fixed version     : ' + fix_display +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, xss:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, report_url);
