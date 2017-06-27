#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80086);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/11/18 21:06:04 $");

  script_name(english:"Information Leakage Vulnerability via MPLS Ping in Huawei VRP Platform (HWPSIRT-2014-0418)");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The firmware version of the remote host is affected by an information
disclosure vulnerability. The MPLS LSP ping service is bound to
unnecessary interfaces which may allow a remote attacker to determine
IP addresses of devices.");
  # http://www.huawei.com/en/security/psirt/security-bulletins/security-advisories/hw-372145.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?697554d8");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patch per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("huawei_vrp_version.nbin");
  script_require_keys("Settings/ParanoidReport", "Host/Huawei/VRP/Series", "Host/Huawei/VRP/Version", "Host/Huawei/VRP/Model");

  exit(0);
}

include("huawei_version.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

model = get_kb_item_or_exit("Host/Huawei/VRP/Model");
series = get_kb_item_or_exit("Host/Huawei/VRP/Series");
version = get_kb_item_or_exit("Host/Huawei/VRP/Version");

reference = make_nested_list(
  make_array(
    "series", make_list("^S(93|77)(00|03|06|12)$"),
    "checks", make_nested_list(
      make_array("vuln", "V100R002", "fix", "V200R003SPH008"),
      make_array("vuln", "V100R003", "fix", "V200R003SPH008"),
      make_array("vuln", "V100R006", "fix", "V200R003SPH008"),
      make_array("vuln", "V200R001", "fix", "V200R003SPH008"),
      make_array("vuln", "V200R002", "fix", "V200R003SPH008"),
      make_array("vuln", "V200R003", "fix", "V200R003SPH008"),
      make_array("vuln", "V200R005", "fix", "V200R003SPH008")
      )
    ),
  make_array(
    "series", make_list("^S97(00|03|06|12)$",
                        "^S93(00|03|06|12)E$"),
    "checks", make_nested_list(
      make_array("vuln", "V200R001", "fix", "V200R003SPH008"),
      make_array("vuln", "V200R002", "fix", "V200R003SPH008"),
      make_array("vuln", "V200R003", "fix", "V200R003SPH008"),
      make_array("vuln", "V200R005", "fix", "V200R003SPH008")
      )
    ),
  make_array(
    "series", make_list("^S127(08|12)$"),
    "checks", make_nested_list(
      make_array("vuln", "V200R005", "fix", "V200R003SPH008")
      )
    ),
  make_array(
    "series", make_list("^5[37]00HI$"),
    "checks", make_nested_list(
      make_array("vuln", "V100R006", "fix", "V200R005CP0001"),
      make_array("vuln", "V200R001", "fix", "V200R005CP0001"),
      make_array("vuln", "V200R002", "fix", "V200R005CP0001"),
      make_array("vuln", "V200R003", "fix", "V200R005CP0001"),
      make_array("vuln", "V200R005", "fix", "V200R005CP0001")
      )
    ),
  make_array(
    "series", make_list("^5[37]10EI$"),
    "checks", make_nested_list(
      make_array("vuln", "V200R002", "fix", "V200R005CP0001"),
      make_array("vuln", "V200R003", "fix", "V200R005CP0001"),
      make_array("vuln", "V200R005", "fix", "V200R005CP0001")
      )
    ),
  make_array(
    "series", make_list("^5[37]10HI$"),
    "checks", make_nested_list(
      make_array("vuln", "V200R003", "fix", "V200R005CP0001"),
      make_array("vuln", "V200R005", "fix", "V200R005CP0001")
      )
    ),
  make_array(
    "series", make_list("^6[37]00EI$"),
    "checks", make_nested_list(
      make_array("vuln", "V200R005", "fix", "V200R005CP0001")
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
