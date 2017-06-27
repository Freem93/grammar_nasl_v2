#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77334);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/23 20:55:07 $");

  script_cve_id("CVE-2013-4631");
  script_bugtraq_id(59628);
  script_osvdb_id(92935);
  script_xref(name:"EDB-ID", value:"25295");

  script_name(english:"Huawei AR Router Remote Command Execution (HWNSIRT-2013-0427)");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Huawei device running a firmware version that is
affected by a remote command execution vulnerability due to a flaw in
the SNMPv3 component. A remote, unauthenticated attacker can
exploit this vulnerability by sending malformed SNMPv3 messages to
execute arbitrary commands.");
  # http://www.huawei.com/en/security/psirt/security-bulletins/security-advisories/hw-260601.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?327116a0");
  script_set_attribute(attribute:"solution", value:"Apply the relevant update referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/25");
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
    "series", make_list("^AR150$", "^AR200$", "^AR[123]200$"),
    "checks", make_nested_list(
      make_array("vuln", "V200R001", "fix", "V200R003C01SPC300"),
      make_array("vuln", "V200R002", "fix", "V200R003C01SPC300"),
      make_array("vuln", "V200R003", "fix", "V200R003C01SPC300")
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
