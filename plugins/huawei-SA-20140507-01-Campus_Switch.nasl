#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77340);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/23 20:55:07 $");

  script_cve_id("CVE-2014-4707");
  script_bugtraq_id(67393);

  script_name(english:"Huawei Campus Switch Multiple Vulnerabilities (HWPSIRT-2014-0315 - HWPSIRT-2014-0318)");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Huawei switch running a firmware version that is
affected by multiple vulnerabilities due to flaws in the Boot and
BootROM menus. A remote, unauthenticated attacker could exploit these
vulnerabilities to take control of the device. ");
  # http://www.huawei.com/en/security/psirt/security-bulletins/security-advisories/hw-334629.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8ea105c");
  script_set_attribute(attribute:"solution", value:"Apply the relevant update referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/22");

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

reference = make_nested_list(
  make_array(
    "series", make_list("^S7700$", "^S9[37]00$"),
    "checks", make_nested_list(
      make_array("vuln", "V200R001C00SPC300", "fix", "V200R003C00SPC500"),
      make_array("vuln", "V200R002C00SPC100", "fix", "V200R003C00SPC500"),
      make_array("vuln", "V200R003C00SPC300", "fix", "V200R003C00SPC500")
      )
    )
  );

huawei_check_and_report(
  model:model,
  series:series,
  version:version,
  reference:reference,
  severity:SECURITY_WARNING
);
