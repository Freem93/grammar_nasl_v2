#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76055);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2014-2602");
  script_bugtraq_id(67197);
  script_osvdb_id(106568);
  script_xref(name:"HP", value:"emr_na-c04273152");

  script_name(english:"HP OneView Unspecified Remote Privilege Escalation (HPSBGN03034)");
  script_summary(english:"Checks version of HP OneView");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an
unspecified, remote privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP OneView installed on the remote host is 1.0 or 1.01.
Such versions are potentially affected by an unspecified, remote
privilege escalation vulnerability.");
  # https://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04273152
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3e961e23");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/May/10");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP OneView 1.05 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:oneview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_oneview_detect.nbin");
  script_require_keys("www/hp_oneview");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443);

install = get_install_from_kb(appname:'hp_oneview', port:port, exit_on_fail:TRUE);

appname = 'HP OneView';
dir = install['dir'];
install_loc = build_url(port:port, qs:dir + "/");

version = install["ver"];
if (version == UNKNOWN_VER)  audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, install_loc);

if ('build' >< version)
{
  ver = version - strstr(version, ' build');
}

if (
  ver =~ '^1\\.0(0)?$' ||
  ver =~ '^1\\.01$'
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_loc +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : 1.05\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_loc, ver);
