#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72416);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/07 15:36:47 $");

  script_cve_id(
    "CVE-2011-4046",
    "CVE-2011-4047",
    "CVE-2011-4048",
    "CVE-2011-4436"
  );
  script_bugtraq_id(50605);
  script_osvdb_id(
    76938,
    76939,
    77209,
    77210,
    127708
  );
  script_xref(name:"TRA", value:"TRA-2011-08");
  script_xref(name:"TRA", value:"TRA-2011-09");
  script_xref(name:"TRA", value:"TRA-2011-10");
  script_xref(name:"TRA", value:"TRA-2011-11");
  script_xref(name:"CERT", value:"135606");
  script_xref(name:"CERT", value:"193529");
  script_xref(name:"CERT", value:"589089");
  script_xref(name:"CERT", value:"702169");

  script_name(english:"Dell KACE K2000 < 3.3.52857 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Dell KACE");

  script_set_attribute(attribute:"synopsis", value:
"The system deployment appliance detected on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Dell KACE K2000 appliance is affected by multiple
vulnerabilities :

  - The appliance stores the recovery account password in
    plaintext within a PHP script. (CVE-2011-4046)

  - The appliance can allow arbitrary command execution by
    leveraging database write access. (CVE-2011-4047)

  - An information disclosure vulnerability exists as the
    appliance contains a default username and password for a
    read-only reporting account. (CVE-2011-4048)

  - The appliance's web interface is affected by multiple
    cross-site scripting (XSS) vulnerabilities.
    (CVE-2011-4436)");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2011-08");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2011-09");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2011-10");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2011-11");
  # http://www.kace.com/support/resources/kb/article/K2000-Appliance-Security-Recommended-Practices?action=artikel&id=1120
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbeb79e3");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.3 SP1 (3.3.52857) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:kace_k2000_systems_deployment_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_require_ports("Services/www", 80);
  script_dependencies("dell_kace_web_detect.nasl");
  script_require_keys("www/dell_kace_k2000");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);
prod = "Dell KACE K2000";

install = get_install_from_kb(
  appname      : "dell_kace_k2000",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
version = install["ver"];
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, prod, install_url);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] < 3) ||
  (ver[0] == 3 && ver[1] < 3) ||
  (ver[0] == 3 && ver[1] == 3 && ver[2] < 52857)
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 3.3.52857 (3.3 SP1)\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, prod, install_url, version);
