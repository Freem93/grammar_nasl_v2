#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81259);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/11 14:11:08 $");

  script_cve_id("CVE-2014-9217");
  script_bugtraq_id(71827);
  script_osvdb_id(115753);

  script_name(english:"Graylog2 LDAP Authentication Bypass Vulnerability");
  script_summary(english:"Checks the Graylog2 version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote version of Graylog2 is affected by a vulnerability that
allows remote attackers, using crafted wildcards, to bypass the
authentication mechanisms when the installation is configured to use
LDAP authentication.");
  script_set_attribute(attribute:"see_also", value:"https://www.graylog2.org/news/post/0010-graylog2-v0-92");
  script_set_attribute(attribute:"solution", value:"Upgrade Graylog2 to version 0.92 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:torch_gmbh:graylog2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("graylog2_web_interface_detect.nbin");
  script_require_ports("Services/www", 443);
  script_require_keys("installed_sw/Graylog2");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

get_install_count(app_name:'Graylog2', exit_if_zero:TRUE);

port = get_http_port(default:443);

install = get_single_install(
  app_name            : 'Graylog2',
  port                : port,
  exit_if_unknown_ver : TRUE
);

version = install['version'];
item = eregmatch(pattern:"^([\d.]+)($|[^\d.])", string:version);

if(isnull(item) || isnull(item[1]))
  audit(AUDIT_NONNUMERIC_VER, 'Graylog2', port, version);

version = item[1];

if(ver_compare(ver:version, fix:'0.92.0', strict:FALSE) == -1)
{
  if(report_verbosity > 0)
  {
    report = '\n  URL               : ' + build_url(port:port, qs:'/') +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 0.92.0\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Graylog2", build_url(port:port, qs:"/"));
