#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90545);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:42:40 $");

  script_cve_id("CVE-2016-2245");
  script_bugtraq_id(84969);
  script_osvdb_id(136051);
  script_xref(name:"HP", value:"emr_na-c05031674");
  script_xref(name:"IAVB", value:"2016-B-0070");
  script_xref(name:"HP", value:"HPSBGN03438");

  script_name(english:"HP Support Assistant < 8.1.52.1 Unspecified Local Authentication Bypass");
  script_summary(english:"Checks the version of HP Support Assistant.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by an
unspecified local authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP Support Assistant installed on the remote Windows
host is prior to 8.1.52.1. It is, therefore, affected by an
unspecified flaw that allows an attacker to bypass local
authentication.");
  # https://h20565.www2.hp.com/hpsc/doc/public/display?docId=emr_na-c05031674
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4af8e69c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Support Assistant version 8.1.52.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:support_assistant");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("hp_support_assistant_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/HP Support Assistant");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "HP Support Assistant";
fix = "8.1.52.1";
install = get_single_install(app_name:app_name);

version = install['version'];
path    = install['path'];

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (empty_or_null(port))
    port = 445;

  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", fix
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );
  security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
