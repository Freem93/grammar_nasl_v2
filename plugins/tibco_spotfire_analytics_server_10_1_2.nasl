#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78391);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/14 00:03:54 $");

  script_cve_id("CVE-2012-0690");
  script_bugtraq_id(52380);
  script_osvdb_id(79979);

  script_name(english:"TIBCO Spotfire Analytics Server Authentication Module Unspecified Information Disclosure");
  script_summary(english:"Checks for TIBCO Spotfire Analytics Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of TIBCO Spotfire Analytics
Server that is affected by an information disclosure vulnerability due
to an unspecified flaw in the Authentication Module. A remote attacker
can exploit this vulnerability to access sensitive information by
sending a specially crafted URL.");
  # http://www.tibco.com/assets/blta17258087ab38cad/spotfire_advisory_20120308_tcm8-15731.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68560144");
  # http://www.tibco.com/services/support/advisories/amx-be-spotfire-advisory_20120308
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a870b3e");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tibco:spotfire_analytics_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencies("tibco_spotfire_server_detect.nbin");
  script_require_keys("installed_sw/TIBCO Spotfire Analytics Server");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80);

app = "TIBCO Spotfire Analytics Server";;
install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

url = build_url(port:port, qs:install['path']);
version = install['version'];

fix = "10.1.2";
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, version);
