#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96449);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/21 03:49:58 $");

  script_cve_id("CVE-2016-8519");
  script_bugtraq_id(95225);
  script_osvdb_id(149561);
  script_xref(name:"HP", value:"HPSBGN03688");
  script_xref(name:"IAVB", value:"2017-B-0004");
  script_xref(name:"HP", value:"emr_na-c05361944");
  script_xref(name:"ZDI", value:"ZDI-17-001");

  script_name(english:"HP Operations Orchestration 10.x < 10.70 wsExecutionBridgeService Servlet Java Object Deserialization RCE");
  script_summary(english:"Checks the HP Operations Orchestration version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP Operations Orchestration running on the remote host
is 10.x prior to 10.70. It is, therefore, affected by a remote code
execution vulnerability in the wsExecutionBridgeService servlet due to
improper validation of user-supplied input before deserialization. An
unauthenticated, remote attacker can exploit this, by sending a
crafted serialized Java object, to execute arbitrary code.

Note that this vulnerability only affects the Community and Enterprise
editions.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05361944
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82646e7d");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-17-001/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Operations Orchestration version 10.70 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:operations_orchestration");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("hp_operations_orchestration_detect.nbin");
  script_require_ports("Services/www", 8080, 8443);
  script_require_keys("installed_sw/HP Operations Orchestration");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "HP Operations Orchestration";

get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:8080);

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);

dir = install['path'];
version = install['version'];
edition = install['Edition'];

install_url = build_url(port:port, qs:dir);

if ("Community" >!< edition && "Enterprise" >!< edition)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname + ' ' + edition, install_url);

fix = "10.70";

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  items = make_array("URL", install_url, "Installed version", version, "Fixed version", fix);
  order = make_list("URL", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
