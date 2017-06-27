#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73349);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/15 04:41:37 $");

  script_cve_id("CVE-2014-0623");
  script_bugtraq_id(66461);
  script_osvdb_id(105016);

  script_name(english:"EMC RSA Authentication Manager 7.x < 7.1 SP4 Patch 32 Unspecified XSS");
  script_summary(english:"Checks version of EMS RSA Authentication Manager.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of EMC RSA Authentication Manager
7 prior to 7.1 SP4 Patch 32. It is, therefore, affected by an
unspecified cross-site scripting vulnerability. An attacker could
potentially exploit this vulnerability to compromise the affected
system.");
  # http://seclists.org/bugtraq/2014/Mar/att-145/ESA-2014-015.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7591153f");
  script_set_attribute(attribute:"solution", value:"Upgrade to 7.1 SP4 Patch 32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:authentication_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
report_url = get_kb_item_or_exit("www/" + port + "/emc_rsa_am/url");
version = get_kb_item_or_exit("www/" + port + "/emc_rsa_am/version");
version_display = get_kb_item_or_exit("www/" + port + "/emc_rsa_am/version_display");

fix = '7.1.4.32';
fix_display = "7.1 SP4 Patch 32";

if (version =~ "^7\." && ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + report_url +
      '\n  Installed version : ' + version_display +
      '\n  Fixed version     : ' + fix_display +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, report_url);
