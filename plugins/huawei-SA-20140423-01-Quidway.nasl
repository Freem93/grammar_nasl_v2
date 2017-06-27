#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76796);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/22 21:31:42 $");

  script_cve_id("CVE-2014-3224");
  script_bugtraq_id(67140);

  script_name(english:"Huawei Quidway Switches DoS (HWPSIRT-2014-0301)");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Huawei Quidway switch running a firmware version
that is affected by a denial of service vulnerability. The issue is
due to a failure to properly validate input. A remote, unauthenticated
attacker could exploit this vulnerability by sending malformed packets
to cause excessive memory consumption or even a device reboot.");
  # http://www.huawei.com/en/security/psirt/security-bulletins/security-advisories/hw-333184.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?114eaec5");
  script_set_attribute(attribute:"solution", value:"Apply the relevant update referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/23");
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

# It seems to me that Huawei uses 'Campus Series' and 'Quidway Series'
# interchangeably but just to be safe, exit out if 'Quidway' is not in
# the model name and this is not a paranoid scan.
if ("Quidway" >!< model && report_paranoia < 2) audit(AUDIT_HOST_NOT, affected_name);

reference = make_nested_list(
  make_array(
    "series", make_list("^S9[73]00$", "^S7700$"),
    "checks", make_nested_list(make_array("vuln", "V200R003C00SPC500", "fix", "V200R003SPH005"))
  ),
  make_array(
    "series", make_list("^S6[73]00$", "^S5[73]00$"),
    "checks", make_nested_list(make_array("vuln", "V200R003C00SPC300", "fix", "V200R003SPH005"))
  )
);

huawei_check_and_report(
  model:model,
  series:series,
  version:version,
  reference:reference,
  severity:SECURITY_HOLE
);
