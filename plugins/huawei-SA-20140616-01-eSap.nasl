#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76797);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/22 21:31:42 $");

  script_cve_id("CVE-2014-4705");
  script_bugtraq_id(68130);
  script_osvdb_id(108186);

  script_name(english:"Huawei eSap Platform DoS (HWPSIRT-2014-0111)");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Huawei device running a firmware version that is
affected by a denial of service vulnerability. The issue stems from a
heap overflow vulnerability in the firmware. A remote, unauthenticated
attacker could exploit this vulnerability by sending malformed packets
to cause excessive memory consumption or a device reboot.");
  # http://www.huawei.com/en/security/psirt/security-bulletins/security-advisories/hw-345171.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c2ae7e8");
  script_set_attribute(attribute:"solution", value:"Apply the relevant update referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:versatile_routing_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("huawei_vrp_version.nbin");
  script_require_keys("Host/Huawei/VRP/Series", "Host/Huawei/VRP/Version", "Host/Huawei/VRP/Model");

  exit(0);
}

include("huawei_version.inc");

model = get_kb_item_or_exit("Host/Huawei/VRP/Model");
series = get_kb_item_or_exit("Host/Huawei/VRP/Series");
version = get_kb_item_or_exit("Host/Huawei/VRP/Version");

affected_name = "Huawei Quidway S-Series Switch";
fix = NULL;

reference = make_nested_list(
  make_array(
    "series", make_list("^S9[73]00$", "^S7700$"),
    "checks", make_nested_list(
      make_array("vuln", "V200R001C00SPC300", "fix", "V200R001SPH016"),
      make_array("vuln", "V200R002C00SPC100", "fix", "V200R005C00SPC300"),
      make_array("vuln", "V200R003C00SPC500", "fix", "V200R003SPH006")
    )
  ),
  make_array(
    "series", make_list("^S5[73]00$", "^S6[73]00$"),
    "checks", make_nested_list(
      make_array("vuln", "V200R001C00SPC300", "fix", "V200R001SPH013"),
      make_array("vuln", "V200R002C00SPC100", "fix", "V200R005C00SPC300"),
      make_array("vuln", "V200R003C00SPC300", "fix", "V200R003SPH006")
    )
  ),
  make_array(
    "series", make_list("^AR1[56]0$", "^AR200$", "^AR[123]200$", "^AR530$", "^16EX$", "^SRG[123]300$"),
    "checks", make_nested_list(
      make_array("vuln", "V200R003C01SPC900", "fix", "V200R003SPH010"),
      make_array("vuln", "V200R003C01SPC300", "fix", "V200R003SPH010"),
      make_array("vuln", "V200R003C01SPC100", "fix", "V200R003SPH010"),
      make_array("vuln", "V200R003C00SPC200", "fix", "V200R003SPH010"),
      make_array("vuln", "V200R003C00SPC100", "fix", "V200R003SPH010"),
      make_array("vuln", "V200R005C00SPC100", "fix", "V200R005C10SPC500 / V200R005SPH002"),
      make_array("vuln", "V200R005C00SPC200", "fix", "V200R005C10SPC500 / V200R005SPH002")
    )
  ),
  make_array(
    "series", make_list("^AC6[60]05$", "^ACU2$"),
    "checks", make_nested_list(make_array("vuln", "V200R005C00SPC100", "fix", "V200R005C00SPC200"))
  )
);

huawei_check_and_report(
  model:model,
  series:series,
  version:version,
  reference:reference,
  severity:SECURITY_HOLE
);
