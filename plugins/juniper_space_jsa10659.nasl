#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80197);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id(
    "CVE-2011-4109",
    "CVE-2011-4576",
    "CVE-2011-4619",
    "CVE-2012-0884",
    "CVE-2012-2110",
    "CVE-2012-2333",
    "CVE-2013-0166",
    "CVE-2013-0169",
    "CVE-2013-5908",
    "CVE-2014-0224",
    "CVE-2014-0411",
    "CVE-2014-0423",
    "CVE-2014-0453",
    "CVE-2014-0460",
    "CVE-2014-4244",
    "CVE-2014-4263",
    "CVE-2014-4264"
  );
  script_bugtraq_id(
    51281,
    52428,
    53158,
    53476,
    57778,
    60268,
    64896,
    64914,
    64918,
    66914,
    66916,
    67899,
    68612,
    68624,
    68636
  );
  script_osvdb_id(
    78187,
    78188,
    78190,
    80039,
    81223,
    81810,
    89848,
    89865,
    102008,
    102028,
    102078,
    105889,
    105897,
    107729,
    109139,
    109141,
    109142
  );

  script_name(english:"Juniper Junos Space < 14.1R1 Multiple Vulnerabilities (JSA10659)");
  script_summary(english:"Checks the version of Junos Space.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos Space
version is prior to 14.1R1. It is, therefore, affected by multiple
vulnerabilities in bundled third party software components :

  - Multiple vulnerabilities in the bundled OpenSSL CentOS
    package. (CVE-2011-4109, CVE-2011-4576, CVE-2011-4619,
    CVE-2012-0884, CVE-2012-2110, CVE-2012-2333,
    CVE-2013-0166, CVE-2013-0169, CVE-2014-0224)

  - Multiple vulnerabilities in Oracle MySQL.
    (CVE-2013-5908)

  - Multiple vulnerabilities in the Oracle Java runtime.
    (CVE-2014-0411, CVE-2014-0423, CVE-2014-4244,
    CVE-2014-0453, CVE-2014-0460, CVE-2014-4263,
    CVE-2014-4264)");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10659");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Junos Space 14.1R1 or later. Alternatively, apply the
workaround referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/12");
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

check_junos_space(ver:ver, fix:'14.1R1', severity:SECURITY_HOLE);
