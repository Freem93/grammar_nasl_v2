#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80193);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id(
    "CVE-2011-2262",
    "CVE-2012-0486",
    "CVE-2012-0553",
    "CVE-2012-0882",
    "CVE-2012-1702",
    "CVE-2012-3147",
    "CVE-2012-3158",
    "CVE-2012-3163",
    "CVE-2013-0385",
    "CVE-2013-1492",
    "CVE-2013-3801"
  );
  script_bugtraq_id(
    51493,
    51514,
    51925,
    56017,
    56022,
    56036,
    57388,
    57412,
    58594,
    58595,
    61269
  );
  script_osvdb_id(
    78376,
    78384,
    78919,
    86260,
    86261,
    86263,
    89254,
    89256,
    91534,
    91536,
    95331
  );

  script_name(english:"Juniper Junos Space < 13.1R1 MySQL Multiple Vulnerabilities (JSA10601)");
  script_summary(english:"Checks the version version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos Space
version is prior to 13.1R1. It is, therefore, affected by multiple
vulnerabilities related to the installed MySQL version.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10601");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Junos Space 13.1R1 or later. Alternatively, apply the
workaround referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_space");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Junos_Space/version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Junos_Space/version');

check_junos_space(ver:ver, fix:'13.1R1', severity:SECURITY_HOLE);
