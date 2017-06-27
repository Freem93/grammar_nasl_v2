#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77391);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/09/02 01:42:14 $");

  script_cve_id("CVE-2014-5394");
  script_bugtraq_id(69302);
  script_osvdb_id(110182);

  script_name(english:"SSH Username Information Disclosure Vulnerability in Huawei Campus Series Switches");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Huawei switch device is affected by an information
disclosure vulnerability. By examining its SSH server response when
attempting a login, a remote attacker can verify whether a guessed
username exists on the device.");
  # http://huawei.com/en/security/psirt/security-bulletins/security-advisories/hw-362701.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30364a09");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate firmware patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/26");

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

affected_name = "Huawei Campus Series Switch";

reference = make_nested_list(
  make_array(
    "series", make_list("^S9300E?$", "^S[79]700$", "^S[65][37]00$"),
    "checks", make_nested_list(
      make_array("vuln", "V200R001C00SPC300", "fix", "V200R005C00SPC300"),
      make_array("vuln", "V200R002C00SPC300", "fix", "V200R005C00SPC300"),
      make_array("vuln", "V200R003C00SPC500", "fix", "V200R005C00SPC300")
    )
  ),
  make_array(
    "series", make_list("^S[23][37]00$"),
    "checks", make_nested_list(
      make_array("vuln", "V100R006C05", "fix", "V100R006SPH018")
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
