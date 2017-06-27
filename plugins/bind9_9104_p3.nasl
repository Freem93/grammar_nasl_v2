#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93865);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/13 17:57:45 $");

  script_cve_id("CVE-2016-2776");
  script_bugtraq_id(93188);
  script_osvdb_id(144854);
  script_xref(name:"EDB-ID", value:"40453");
  script_xref(name:"IAVA", value:"2017-A-0004");

  script_name(english:"ISC BIND 9.9.x < 9.9.9-P3 / 9.10.x < 9.10.4-P3 / 9.11.x < 9.11.0rc3 buffer.c Query Response DoS");
  script_summary(english:"Checks the version of BIND.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of ISC
BIND running on the remote name server is 9.9.x prior to 9.9.9-P3,
9.10.x prior to 9.10.4-P3, or 9.11.x prior to 9.11.0rc3. It is,
therefore, affected by a denial of service vulnerability within file
buffer.c due to improper construction of responses to crafted
requests. An unauthenticated, remote attacker can exploit this, via a
specially crafted query, to cause an assertion failure, resulting in a
daemon exit.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01419");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ISC BIND version 9.9.9-P3 / 9.9.9-S5 / 9.10.4-P3 /
9.11.0rc3 or later. Note that BIND 9 version 9.9.9-S5 is available
exclusively for eligible ISC Support customers.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

vcf::bind::initialize();

app_info = vcf::get_app_info(app:"BIND", port:53, kb_ver:"bind/version", service:TRUE, proto:"UDP");

if (report_paranoia < 2) audit(AUDIT_PARANOID); # patch can be applied

constraints = [
  { "min_version" : "9.9.3-S", "fixed_version" : "9.9.9-S4" },
  { "min_version" : "9.9.0", "fixed_version" : "9.9.9-P3" },
  { "min_version" : "9.10.0", "fixed_version" : "9.10.4-P3" },
  { "min_version" : "9.11.0a", "fixed_version" : "9.11.0rc3" }
];
constraints = vcf::bind::filter_constraints(constraints:constraints, version:app_info.version);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
