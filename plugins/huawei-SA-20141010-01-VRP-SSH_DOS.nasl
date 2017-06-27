#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83162);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/05/01 13:43:00 $");

  script_cve_id("CVE-2014-8572");
  script_osvdb_id(113101);
  script_bugtraq_id(70891);

  script_name(english:"Huawei SSH DoS (HWPSIRT-2014-0701)");
  script_summary(english:"Checks the firmware version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");

  script_set_attribute(attribute:"description", value:
"The remote device is a Huawei router running a firmware version that
is affected by a denial of service vulnerability in its SSH server
service. A remote, unauthenticated attacker can leverage this flaw to
deny access to the device via a specially crafted SSH login packet.");
  # http://www.huawei.com/en/security/psirt/security-bulletins/security-advisories/archive/hw-373182.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d8a01e9");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant update referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:huawei:versatile_routing_platform");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("huawei_vrp_version.nbin");
  script_require_keys("Host/Huawei/VRP/Series", "Host/Huawei/VRP/Version", "Host/Huawei/VRP/Model","Host/Huawei/VRP/display_patch-information");

  exit(0);
}

include("huawei_version.inc");

model = get_kb_item_or_exit("Host/Huawei/VRP/Model");
series = get_kb_item_or_exit("Host/Huawei/VRP/Series");
version = get_kb_item_or_exit("Host/Huawei/VRP/Version");
patchlist = get_kb_item_or_exit("Host/Huawei/VRP/display_patch-information");

reference = make_nested_list(
  make_array(
    "series", make_list("^S(77|97)00$","^S9300E?$"),
    "checks", make_nested_list(
      make_array(
        "vuln", "V200R005C00SPC500",
        "fix", "V200R005C00SPC500+V200R005SPH001",
        "patches", make_nested_list("V200R005SPH001")
        ),
      make_array(
          "vuln", "V200R003",
          "fix", "V200R005C00SPC500+V200R005SPH001",
          "patches", make_nested_list("V200R005SPH001")
        ),
      make_array(
          "vuln", "V200R002",
          "fix", "V200R005C00SPC500+V200R005SPH001",
          "patches", make_nested_list("V200R005SPH001")
        ),
      make_array(
          "vuln", "V200R001",
          "fix", "V200R005C00SPC500+V200R005SPH001",
          "patches", make_nested_list("V200R005SPH001")
        ),
      make_array(
          "vuln", "V100R006",
          "fix", "V200R005C00SPC500+V200R005SPH001",
          "patches", make_nested_list("V200R005SPH001")
        )
      )
    ),
  make_array(
    "series", make_list("^S(53|57|63|67)00$"),
    "checks", make_nested_list(
      make_array(
        "vuln", "V200R005C00SPC300",
        "fix", "V200R005C00SPC300+V200R005CP0001",
        "type", HV_CHECK_EARLIER,
        "patches", make_nested_list("V200R005CP0001")
       ),
      make_array(
          "vuln", "V200R003",
          "fix", "V200R005C00SPC300+V200R005CP0001",
          "patches", make_nested_list("V200R005CP0001")
        ),
      make_array(
          "vuln", "V200R002",
          "fix", "V200R005C00SPC300+V200R005CP0001",
          "patches", make_nested_list("V200R005CP0001")
        ),
      make_array(
          "vuln", "V200R001",
          "fix", "V200R005C00SPC300+V200R005CP0001",
          "patches", make_nested_list("V200R005CP0001")
        ),
      make_array(
          "vuln", "V100R006",
          "fix", "V200R005C00SPC300+V200R005CP0001",
          "patches", make_nested_list("V200R005CP0001")
        )
      )
    ),
  make_array(
    "series", make_list("^S(23|33|27|37)00$"),
    "checks", make_nested_list(
      make_array(
        "vuln", "V100R006C05",
        "fix", "V100R006C05+V100R006CP0001",
        "type", HV_CHECK_EARLIER,
        "patches", make_nested_list("V100R006CP0001")
        )
      )
    ),
  make_array(
    "series", make_list("^ACU$"),
    "checks", make_nested_list(
      make_array(
        "vuln", "V200R002C00",
        "fix", "V200R002C00SPH601"
        ),
      make_array(
        "vuln", "V200R001C00",
        "fix", "V200R002C00SPH601"
        )
      )
    ),
  make_array(
    "series", make_list("^AC6605$"),
    "checks", make_nested_list(
      make_array(
        "vuln", "V200R002C00",
        "fix", "V200R005C00SPC600"
        ),
      make_array(
        "vuln", "V200R001C00",
        "fix", "V200R005C00SPC600"
        )
      )
    )
  );

huawei_check_and_report(
  model:model,
  series:series,
  version:version,
  reference:reference,
  patchlist:patchlist,
  severity:SECURITY_HOLE
);
