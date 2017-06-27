#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85160);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2015-2859");
  script_bugtraq_id(75020);
  script_osvdb_id(122907);
  script_xref(name:"CERT", value:"264092");
  script_xref(name:"MCAFEE-SB", value:"SB10120");

  script_name(english:"McAfee ePolicy Orchestrator SSL/TLS Certificate Validation Security Bypass Vulnerability (SB10120)");
  script_summary(english:"Checks the ePO App Server version.");

  script_set_attribute(attribute:"synopsis", value:
"A security management application running on the remote host is
affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the McAfee ePolicy
Orchestrator (ePO) running on the remote host is affected by a
security bypass vulnerability due to a failure to properly validate
server and Certificate Authority names in X.509 certificates from SSL
servers. A man-in-the-middle attacker, by using a crafted certificate,
can exploit this flaw to spoof servers, thus gaining access to
transmitted information.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10120");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=KB84628");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee ePO version 4.6.9 / 5.1.2 / 5.3.0 or later, and
apply the vendor-supplied workaround.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_epo_app_server_detect.nasl");
  script_require_keys("installed_sw/epo_app_server", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

app_report_name = "McAfee ePO";
app_name = 'epo_app_server';

get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:8443);

install = get_single_install(
  app_name : app_name,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['dir'];
ver = install['version'];
url = build_url(qs:dir, port:port);

# Cannot determine if workaround is in place
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# 4.5.x and 4.6.x <= 4.6.9
# 5.0.x and 5.1.x <= 5.1.2
# 5.3.0
if
(
  (ver =~ "^4\.[56]\." && ver_compare(ver:ver, fix:"4.6.9", strict:FALSE) <= 0)
  ||
  (ver =~ "^5\.[01]\." && ver_compare(ver:ver, fix:"5.1.2", strict:FALSE) <= 0)
  ||
  (ver =~ "^5\.3\.0($|[^0-9])")
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : See solution.' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_report_name, url, ver);
