#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90628);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/02 15:19:31 $");

  script_cve_id("CVE-2015-7182");
  script_bugtraq_id(77416);
  script_osvdb_id(129798);

  script_name(english:"Oracle iPlanet Web Server 7.0.x < 7.0.23 NSS ASN.1 Decoder RCE (April 2016 CPU)");
  script_summary(english:"Checks the version in the admin console.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Oracle iPlanet Web Server
(formerly known as Sun Java System Web Server) running on the remote 
host is 7.0.x prior to 7.0.23. It is, therefore, affected by a heap
buffer overflow condition in the ASN.1 decoder in the Network Security
Services (NSS) library. A remote attacker can exploit this, via
crafted OCTET STRING data, to cause a denial of service or to execute
arbitrary code.");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?855180af");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2016-2881694.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f84b6b0a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle iPlanet Web Server version 7.0.23 or later as
referenced in the April 2016 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:iplanet_web_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:network_security_services");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_iplanet_web_server_detect.nbin");
  script_require_keys("installed_sw/Oracle iPlanet Web Server");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

app_name = "Oracle iPlanet Web Server";
port = get_http_port(default:8989);

install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];

fix = "7.0.23";
min = "7.0";

# Affected 7.0.x < 7.0.23
if (
  ver_compare(ver:version, fix:min, strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fix, strict:FALSE) == -1
)
{
  report = report_items_str(
    report_items:make_array(
      "Installed version", version,
      "Fixed version", fix
    ),
    ordered_fields:make_list("Installed version", "Fixed version")
  );
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
