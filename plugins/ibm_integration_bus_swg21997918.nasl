#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97578);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/03/10 16:46:29 $");

  script_cve_id("CVE-2016-9706");
  script_bugtraq_id(96274);
  script_osvdb_id(148474);
  script_xref(name:"IAVB", value:"2017-B-0021");

  script_name(english:"IBM Integration Bus 8.x < 8.0.0.8 / 9.x < 9.0.0.6 / 10.x < 10.0.0.5 SOAP FLOWS XXE DoS");
  script_summary(english:"Checks the version of IBM Integration Bus.");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise service bus application installed on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Integration Bus (formerly known as IBM WebSphere
Message Broker) is 8.x prior to 8.0.0.8, 9.x prior to 9.0.0.6, or 10.x
prior to 10.0.0.5. It is, therefore, affected by a denial of service
vulnerability due to an XML external entity (XXE) injection error in
SOAP FLOWS when processing XML data. An unauthenticated, remote
attacker can exploit this to disclose sensitive information or cause a
denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21997918");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Integration Bus version 8.0.0.8 / 9.0.0.6 / 10.0.0.5 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_message_broker");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:integration_bus");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ibm_integration_bus_installed.nbin");
  script_require_keys("installed_sw/IBM Integration Bus");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'IBM Integration Bus';
get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(app_name: app, exit_if_unknown_ver: TRUE);

path = install['path'];
version = install['version'];

if (version =~ "^10\.")
  fix = "10.0.0.5";
else if (version =~ "^9\.")
  fix = "9.0.0.6";
else if (version =~ "^8\.")
  fix = "8.0.0.8";
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

order = make_list("Installed version", "Fixed version", "Path");
report = make_array(
  order[0], version,
  order[1], fix,
  order[2], path
);
report = report_items_str(report_items:report, ordered_fields:order);

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
