#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77337);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/11/18 21:03:57 $");

  script_cve_id("CVE-2014-1688");
  script_bugtraq_id(64634);
  script_osvdb_id(101637);

  script_name(english:"Huawei CloudEngine Switch Security Bypass (HWPSIRT-2013-1256)");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Huawei switch running a firmware version that is
affected by a security bypass vulnerability due to a failure of access
control. An authenticated attacker can exploit this vulnerability to
execute commands with higher-level permissions.");
  # http://www.huawei.com/en/security/psirt/security-bulletins/security-advisories/hw-323610.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?898480dd");
  script_set_attribute(attribute:"solution", value:"Apply the relevant update referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:versatile_routing_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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
    "series", make_list("^CE[56]800$"),
    "checks", make_nested_list(
      make_array(
        "vuln", "V100R001C00SPC200",
        "fix", "V100R002C00SPC200 / V100R001SPH001",
        "type", HV_CHECK_EARLIER
        )
      )
    ),
  make_array(
    "series", make_list("^CE12800$"),
    "checks", make_nested_list(
      make_array(
        "vuln", "V100R001C00SPC200",
        "fix", "V100R002C00SPC200 / V100R001SPH001",
        "type", HV_CHECK_EARLIER
        ),
      make_array(
        "vuln", "V100R001C01SPC100",
        "fix", "V100R002C00SPC200 / V100R001SPH001",
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
  severity:SECURITY_HOLE
);
