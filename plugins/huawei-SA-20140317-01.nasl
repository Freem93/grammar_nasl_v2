#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77339);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/11/18 21:03:57 $");

  script_cve_id("CVE-2014-3223");
  script_bugtraq_id(66284);
  script_osvdb_id(104676);

  script_name(english:"Huawei Switch DoS (HWPSIRT-2013-1165)");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Huawei switch running a firmware version that is
affected by a denial of service vulnerability due to a flaw in Y.1731.
A remote, unauthenticated attacker could exploit this vulnerability by
sending specially crafted packets to cause a device restart.");
  # http://www.huawei.com/en/security/psirt/security-bulletins/security-advisories/hw-329625.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a84b05f");
  script_set_attribute(attribute:"solution", value:"Apply the relevant update referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/17");
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
    "series", make_list("^S[2356]300$"),
    "checks", make_nested_list(
      make_array("vuln", "V100R006C00SPC800", "fix", "V100R006SPH010"),
      make_array("vuln", "V100R006C01SPC100", "fix", "V100R006SPH010"),
      make_array("vuln", "V100R006C03", "fix", "V100R006SPH010")
      )
    )
  );

if (report_paranoia > 1) reference[1] =
  make_array(
    "series", make_list("^S9300$"),
    "checks", make_nested_list(
      make_array("vuln", "V100R006C00SPC500", "fix", "V100R006SPH013"),
      make_array("vuln", "V100R006C00SPC800", "fix", "V100R006SPH013")
    )
  );

huawei_check_and_report(
  model:model,
  series:series,
  version:version,
  reference:reference,
  severity:SECURITY_HOLE
);
