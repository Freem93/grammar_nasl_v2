#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90627);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/28 18:42:40 $");

  script_cve_id("CVE-2015-7182");
  script_bugtraq_id(77416);
  script_osvdb_id(129798);

  script_name(english:"Oracle iPlanet Web Proxy Server 4.0.x < 4.0.27 NSS ASN.1 Decoder RCE (April 2016 CPU)");
  script_summary(english:"Checks the proxyd.exe product version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web proxy server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Oracle iPlanet Web Proxy
Server (formerly known as Sun Java System Web Proxy Server) installed 
on the remote host is version 4.0.x prior to 4.0.27. It is, therefore, 
affected by a heap buffer overflow condition in the ASN.1 decoder in
the Network Security Services (NSS) library. A remote attacker can
exploit this, via crafted OCTET STRING data, to cause a denial of
service or to execute arbitrary code.");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?855180af");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2016-2881694.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f84b6b0a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle iPlanet Web Proxy Server version 4.0.27 or later as
referenced in the April 2016 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:iplanet_web_proxy_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:network_security_services");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("iplanet_web_proxy_installed.nbin");
  script_require_keys("installed_sw/Oracle iPlanet Web Proxy Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = 'Oracle iPlanet Web Proxy Server';

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

fixed_version = '4.0.27';
min_version   = '4.0';

if (
  ver_compare(ver:version, fix:min_version, strict:FALSE) >= 0 &&
  ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", fixed_version
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
