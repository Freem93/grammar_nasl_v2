#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88094);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2016-1260");
  script_osvdb_id(132867);
  script_xref(name:"JSA", value:"JSA10719");

  script_name(english:"Juniper Junos Network Topology Loop DoS (JSA10719)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a denial of service vulnerability due to a
flaw in the Spanning Tree Protocol implementation. An unauthenticated,
remote attacker can exploit this, via specially crafted packets that
create an artificial loop in the network topology, to cause excessive
bandwidth usage.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10719");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10719.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

if (model !~ "EX43[0-9][0-9]")
    audit(AUDIT_HOST_NOT, 'EX4300-Series');

fixes['13.2X51'] = '13.2X51-D36'; # or 13.2X51-D39
fixes['14.1X53'] = '14.1X53-D25'; # or 14.1X53-D26
fixes['15.2R'  ] = '15.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix ==  "13.2X51-D36")
  fix += " or 13.2X51-D39";
if (fix == "14.1X53-D25")
  fix += " or 14.1X53-D26";

junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_WARNING);
