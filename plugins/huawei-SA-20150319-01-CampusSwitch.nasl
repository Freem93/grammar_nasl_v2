#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82430);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/31 13:56:06 $");

  script_bugtraq_id(73355);
  script_osvdb_id(119769);

  script_name(english:"Huawei Campus Series Switches Remote Buffer Overflow DoS (HWPSIRT-2015-02014)");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Huawei switch is affected by a denial of service
vulnerability due to improper validation of user-supplied input to the
service processing function. A remote attacker, using a specially
crafted username, can cause an array access violation, resulting in a
restart of the device.");
  # http://www.huawei.com/en/security/psirt/security-bulletins/security-advisories/archive/hw-418554.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af6d1703");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate firmware patch per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:versatile_routing_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("huawei_vrp_version.nbin");
  script_require_keys("Host/Huawei/VRP/Series", "Host/Huawei/VRP/Version", "Host/Huawei/VRP/Model");

  exit(0);
}

include("huawei_version.inc");

model = get_kb_item_or_exit("Host/Huawei/VRP/Model");
series = get_kb_item_or_exit("Host/Huawei/VRP/Series");
version = get_kb_item_or_exit("Host/Huawei/VRP/Version");

affected_name = "Huawei Campus Series Switch";

reference = make_nested_list(
    make_array(
      "series", make_list("^S(53|57|63|67)00$"),
      "checks", make_nested_list(
        make_array("vuln", "V200R001C00SPC300", "fix", "V200R001SPH012")
      )
    ),
    make_array(
      "series", make_list("^S(77|93|97)00$"),
      "checks", make_nested_list(
        make_array("vuln", "V200R001C00SPC300", "fix", "V200R001SPH015")
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
