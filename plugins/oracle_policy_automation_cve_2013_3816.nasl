#
# (C) Tenable Network Security, Inc.
#

app = "Oracle Web Determinations";
cpe = "cpe:/a:oracle:industry_applications";

include("compat.inc");

if (description)
{
  script_id(77667);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/09/12 17:31:25 $");

  script_cve_id("CVE-2013-3816");
  script_bugtraq_id(61243);
  script_osvdb_id(95302);

  script_name(english:"Oracle Policy Automation (Oracle Web Determinations) Unspecified Remote Security Vulnerability (July 2013 CPU)");
  script_summary(english:"Checks the version of the Policy Automation component.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by an unspecified remote vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Policy Automation installed on the remote host
is 10.2.x prior to 10.2.0.124, 10.3.x prior to 10.3.1.61, or 10.4.x
prior to 10.4.3. It is, therefore, affected by an unspecified remote
vulnerability that can be exploited by remote authenticated users to
disclose sensitive information.");
  # http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d601a70e");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2013 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:cpe);
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_web_determinations_detect.nbin");
  script_require_keys("installed_sw/" + app);
  script_require_ports("Services/www", 7001);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:7001);

get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];

fix = "";

# 10.2.x < 10.2.0.124
if (version =~ "^10\.2\." &&
     ver_compare(ver:version, fix:"10.2.0.124", strict:FALSE) == -1)
  fix = "10.2.0.124";

# 10.3.x < 10.3.1.61
if (version =~ "^10\.3\." &&
     ver_compare(ver:version, fix:"10.3.1.61", strict:FALSE) == -1)
  fix = "10.3.1.61";

# 10.4.x < 10.4.3
if (version =~ "^10\.4\." &&
     ver_compare(ver:version, fix:"10.4.3", strict:FALSE) == -1)
  fix = "10.4.3";

if (fix != "")
{
  if (report_verbosity > 0)
  {
    report = '\n  URL               : ' + build_url(port:port, qs:path) + 
             '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fix +
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
