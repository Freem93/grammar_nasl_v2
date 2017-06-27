#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77336);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/11 13:32:18 $");

  script_cve_id("CVE-2013-4628");
  script_bugtraq_id(60710);
  script_osvdb_id(93469);

  script_name(english:"Huawei Campus Switch Information Disclosure (HWNSIRT-2013-0317)");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Huawei switch running a firmware version that is
affected by an information disclosure vulnerability due to a failure
of access control. An authenticated, 'low priority security zone'
attacker can exploit this vulnerability to access 'high priority
security zone' areas of the device.");
  # http://www.huawei.com/en/security/psirt/security-bulletins/security-advisories/hw-261458.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08cd75e8");
  script_set_attribute(attribute:"solution", value:"Apply the relevant update referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:versatile_routing_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("huawei_vrp_version.nbin");
  script_require_keys("Host/Huawei/VRP/Series", "Host/Huawei/VRP/Version", "Host/Huawei/VRP/Model");

  exit(0);
}

include("huawei_version.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

model = get_kb_item_or_exit("Host/Huawei/VRP/Model");
series = get_kb_item_or_exit("Host/Huawei/VRP/Series");
version = get_kb_item_or_exit("Host/Huawei/VRP/Version");

reference = make_nested_list(
  make_array(
    "series", make_list("^S7700$", "^S9[73]00$"),
    "checks", make_nested_list(
      make_array("vuln", "V200R001C00SPC300", "fix", "V200R001SPH003"),
      make_array("vuln", "V200R001C10SPC300", "fix", "V200R001SPH003")
      )
  )
);

huawei_check_and_report(
  model:model,
  series:series,
  version:version,
  reference:reference,
  severity:SECURITY_NOTE
);
