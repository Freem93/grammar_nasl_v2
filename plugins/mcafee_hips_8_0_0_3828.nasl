#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95469);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2016-8007");
  script_bugtraq_id(93813);
  script_osvdb_id(146142);
  script_xref(name:"MCAFEE-SB", value:"SB10173");
  script_xref(name:"IAVB", value:"2016-B-0170");

  script_name(english:"McAfee Host Intrusion Prevention Services < 8.0.0.3828 Authentication Bypass (SB10173)");
  script_summary(english:"Checks the version of McAfee Host Intrusion Prevention.");

  script_set_attribute(attribute:"synopsis", value:
"A security application installed on the remote host is affected by an
authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Host Intrusion Prevention Services (HIPS) is
prior to 8.0.0.3828. It is, therefore, affected by an authentication
bypass vulnerability due to improper registry key permissions. A local
attacker can exploit this, under certain conditions, to manipulate the
product's registry keys.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10173");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=KB70778");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Host Intrusion Prevention Services 8.0 Patch 8
(8.0.0.3828) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:host_intrusion_prevention");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_hips_installed.nbin");
  script_require_keys("installed_sw/McAfee Host Intrusion Prevention");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'McAfee Host Intrusion Prevention';
get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(app_name: app, exit_if_unknown_ver: TRUE);

path = install['path'];
version = install['version'];

# all prior to 8.0 Patch 8
fix = "8.0.0.3828";

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

security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
