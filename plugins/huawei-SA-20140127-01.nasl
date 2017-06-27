#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77338);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/23 20:55:07 $");

  script_cve_id("CVE-2014-3221");
  script_bugtraq_id(65197);

  script_name(english:"Huawei Eudemon8000E Firewall DoS (HWPSIRT-2014-0101)");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Huawei switch running a firmware version that is
affected by a denial of service vulnerability. A remote,
unauthenticated attacker could exploit this vulnerability by sending a
large amount of TCP packets to the device, preventing legitimate users
from logging in via SSH or Telnet.");
  # http://www.huawei.com/en/security/psirt/security-bulletins/security-advisories/hw-325385.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c373b952");
  script_set_attribute(attribute:"solution", value:"Apply the relevant update referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/27");
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
    "series", make_list("^Eudemon8000E$"),
    "checks", make_nested_list(
      make_array(
        "vuln", "V200R001C01SPC800",
        "fix", "V200R001C01SPC900",
        "type", HV_CHECK_EARLIER
        )
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
