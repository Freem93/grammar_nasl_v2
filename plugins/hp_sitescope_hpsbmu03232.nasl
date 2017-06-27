#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81206);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/22 14:57:57 $");

  script_cve_id("CVE-2014-7882");
  script_bugtraq_id(72459);
  script_osvdb_id(117553);
  script_xref(name:"HP", value:"emr_na-c04539443");
  script_xref(name:"HP", value:"HPSBMU03232");
  script_xref(name:"HP", value:"SSRT101782");
  script_xref(name:"HP", value:"HPSN-2008-002");

  script_name(english:"HP SiteScope 11.1x < 11.13 or 11.2x < 11.24 IP3 Remote Privilege Escalation");
  script_summary(english:"Checks the version of HP SiteScope.");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by a
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self reported version, the installation of HP
SiteScope on the remote host is 11.1x prior to 11.13 or 11.2x prior to
11.24 IP3. It is, therefore, affected by a privilege escalation
vulnerability where authorized users can gain privileges not assigned
to their role on the system.");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04539443
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e363202c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 11.13 / 11.24 IP3 or later. Alternatively, apply
the appropriate patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:sitescope");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_sitescope_detect.nasl");
  script_require_keys("installed_sw/sitescope");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "sitescope";
# Stops get_http_port from branching
get_install_count(app_name:appname, exit_if_zero:TRUE);

port    = get_http_port(default:8080);
install = get_single_install(app_name:appname,port:port,exit_if_unknown_ver:TRUE);
version = install['version']; # Version level always at least Major.Minor.SP
url     = install['path'   ];
url     = build_url(port:port,qs:url);

if (
  (version =~ "^11\.1[0-2]$") ||
  (version =~ "^11\.2[0-3]$") ||
  # 11.24/11.13 can be affected if they aren't patched
  (version == "11.24" && report_paranoia >= 2) ||
  (version == "11.13" && report_paranoia >= 2)
)
{
  if (report_verbosity > 0)
  {
    fix = "11.24 IP3";
    if(version =~ "^11.1")
      fix = "11.13 with vendor patch";
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
