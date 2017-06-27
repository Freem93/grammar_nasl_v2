#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89057);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/03/01 21:42:32 $");

  script_osvdb_id(134752);

  script_name(english:"Huawei Switches Permission Control Privilege Escalation (HWPSIRT-2015-08048)");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Huawei switch is affected by a privilege escalation
vulnerability related to improper interaction of user permissions when
Authentication, Authorization, and Accounting (AAA) are enabled for
permission control on the switch. An authenticated, remote attacker
can exploit this to access the virtual type terminal (VTY) for gaining
elevated privileges.");
  # http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20160217-01-switch-en
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b93d8c11");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate firmware patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:versatile_routing_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("huawei_vrp_version.nbin");
  script_require_keys("Host/Huawei/VRP/Series", "Host/Huawei/VRP/Version", "Host/Huawei/VRP/Model", "Settings/ParanoidReport");

  exit(0);
}

include("huawei_version.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

patchlist = get_kb_item_or_exit("Host/Huawei/VRP/display_patch-information");
model = get_kb_item_or_exit("Host/Huawei/VRP/Model");
series = get_kb_item_or_exit("Host/Huawei/VRP/Series");
version = get_kb_item_or_exit("Host/Huawei/VRP/Version");

reference = make_nested_list(
    make_array(
      "series", make_list("^S[5679]700$"),
      "checks", make_nested_list(
        make_array("vuln", "V200R001C00SPC300", "fix", "Upgrade to version V200R005C00SPC500, install patch V200R005SPH009"),
        make_array("vuln", "V200R002C00SPC100", "fix", "Upgrade to version V200R005C00SPC500, install patch V200R005SPH009"),
        make_array("vuln", "V200R003C00SPC300", "fix", "Upgrade to version V200R005C00SPC500, install patch V200R005SPH009"),
        make_array("vuln", "V200R005C00SPC500", "fix", "Install patch V200R005SPH009", "patches", make_list("V200R005SPH009")),
        make_array("vuln", "V200R006C00", "fix", "Upgrade to version V200R007C00SPC500")
      )
    ),
    make_array(
      "series", make_list("^S12700$"),
      "checks", make_nested_list(
        make_array("vuln", "V200R005C00SPC500", "fix", "Install patch V200R005SPH009", "patches", make_list("V200R005SPH009")),
        make_array("vuln", "V200R006C00", "fix", "Upgrade to version V200R007C00SPC500")
      )
    ),
    make_array(
      "series", make_list("^ACU2$"),
      "checks", make_nested_list(
        make_array("vuln", "V200R005C00SPC500", "fix", "Upgrade to version V200R007C00SPC500"),
        make_array("vuln", "V200R006C00", "fix", "Upgrade to version V200R006C10SPC200")
      )
    )
);

huawei_check_and_report(
  model:model,
  series:series,
  version:version,
  reference:reference,
  patchlist:patchlist,
  severity:SECURITY_WARNING
);
