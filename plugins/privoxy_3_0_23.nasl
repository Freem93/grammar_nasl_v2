#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81516);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/26 14:38:27 $");

  script_cve_id("CVE-2015-1380", "CVE-2015-1381", "CVE-2015-1382");
  script_bugtraq_id(72354, 72355, 72360);
  script_osvdb_id(117541, 117610, 117609);

  script_name(english:"Privoxy < 3.0.23 Multiple DoS Vulnerabilities");
  script_summary(english:"Checks the version of Privoxy.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web proxy is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Privoxy
running on the remote host is prior to 3.0.23. It is, therefore,
potentially affected by multiple denial of service vulnerabilities :

  - A flaw exists in the chunked_body_is_complete() function
    in 'jcc.c' due to improper processing of invalid
    chunk-encoded bodies. A remote attacker, using a
    specially crafted client request, can cause the Privoxy
    instance to abort. (CVE-2015-1380)

  - Multiple flaws exist in the pcrs_compile_replacement()
    function in 'pcrs.c' when handling backreferences.
    Remote attackers can exploit these flaws to cause a
    segmentation fault or memory consumption.
    (CVE-2015-1381)

  - An invalid read flaw in 'parsers.c' allows a remote
    attacker, via an HTTP request with a specially-crafted
    time header, to cause a denial of service condition.
    (CVE-2015-1382)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/p/ijbswa/mailman/message/33089172/");
  # http://ijbswa.cvs.sourceforge.net/viewvc/ijbswa/current/jcc.c?r1=1.433&r2=1.434
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02038803");
  # http://ijbswa.cvs.sourceforge.net/viewvc/ijbswa/current/pcrs.c?r1=1.46&r2=1.47
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e70b2d80");
  # http://ijbswa.cvs.sourceforge.net/viewvc/ijbswa/current/parsers.c?r1=1.297&r2=1.298
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc0894c2");
  script_set_attribute(attribute:"solution", value:"Upgrade to Privoxy version 3.0.23 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:privoxy:privoxy");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("privoxy_detect.nasl");
  script_require_keys("www/Privoxy", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8118);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:8118);
app_name = "Privoxy";

install = get_install_from_kb(
  appname      : app_name,
  port         : port,
  exit_on_fail : TRUE
);

version = install["ver"];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app_name, port);

install_url = build_url(qs:install["dir"], port:port);
fix = "3.0.23";

# Versions < 3.0.23 are vulnerable
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
