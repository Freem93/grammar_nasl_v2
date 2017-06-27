#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80442);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/06/10 21:03:58 $");

  script_cve_id("CVE-2014-8272");
  script_bugtraq_id(71750);
  script_osvdb_id(116029);
  script_xref(name:"CERT", value:"843044");
  script_xref(name:"EDB-ID", value:"35770");

  script_name(english:"Dell iDRAC Products IPMI Arbitrary Command Injection Vulnerability");
  script_summary(english:"Checks the iDRAC version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an arbitrary command injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of iDRAC that ships with a
version of IPMI that does not sufficiently randomize session ID
values. An unauthenticated, remote attacker can exploit this to inject
arbitrary commands into a privileged session.");
  script_set_attribute(attribute:"see_also", value:"http://www.kb.cert.org/vuls/id/843044");
  script_set_attribute(attribute:"solution", value:"See the advisory for links to vendor patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intel:ipmi");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:remote_access_card");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac6");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:idrac7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("drac_detect.nasl");
  script_require_keys("installed_sw/iDRAC");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "iDRAC";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
fw_version = install['Firmware Version'];
install_url = build_url(port:port, qs:dir);

if (version !~ "^(6|7)")
  audit(AUDIT_WRONG_WEB_SERVER, port, "iDRAC6 / iDRAC7 and therefore is not affected");

fix = '';

if(version =~ "^6($|\.)" &&
   fw_version =~ "^3\." &&
   ver_compare(ver:fw_version, fix:'3.65', strict:FALSE) == -1)
  fix = '3.65';

else if(version =~ "^6($|\.)" &&
        fw_version =~ "^1\." &&
        ver_compare(ver:fw_version, fix:'1.98', strict:FALSE) == -1)
  fix = '1.98';

else if(version =~ "^7($|\.)" &&
        fw_version =~ "^1\." &&
        ver_compare(ver:fw_version, fix:'1.57.57', strict:FALSE) == -1)
  fix = '1.57.57';

if(fix != '')
{
  items = make_array(
    "URL", install_url,
    "iDRAC version", version,
    "Firmware version", fw_version,
    "Fixed version", fix
  );
  order = make_list("URL","iDRAC version","Firmware version","Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app + version, install_url, fw_version);
