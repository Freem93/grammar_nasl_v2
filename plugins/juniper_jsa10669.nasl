#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80957);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id(
    "CVE-2011-1944",
    "CVE-2012-0841",
    "CVE-2012-5134",
    "CVE-2013-0338",
    "CVE-2013-2877"
  );
  script_bugtraq_id(48056, 52107, 56684, 58180, 61050);
  script_osvdb_id(73248, 79437, 87882, 90631, 95032);

  script_name(english:"Juniper Junos libxml2 Library Multiple Vulnerabilities (JSA10669)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by multiple vulnerabilities in the libxml2 library :

  - A heap-based buffer overflow vulnerability exists which
    can result in arbitrary code execution. (CVE-2011-1944)

  - A denial of service vulnerability exists which can
    result in excessive CPU consumption. (CVE-2012-0841)

  - A heap-based buffer overflow vulnerability exists in
    the 'xmlParseAttValueComplex' function which can result
    in arbitrary code execution. (CVE-2012-5134)

  - A denial of service vulnerability exists due to
    excessive CPU and memory consumption in the processing
    of XML files containing entity declarations with long
    replacement text (also known as 'internal entity
    expansion with linear complexity'). (CVE-2013-0338)

  - A denial of service vulnerability exists related to the
    XML_PARSER_EOF state checking. (CVE-2013-2877)

These vulnerabilities can be exploited by a remote attacker via a
specially crafted XML file.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10669");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
JSA10669.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("junos.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['11.4']    = '11.4R13';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D30';
fixes['12.1X46'] = '12.1X46-D25';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.2']    = '12.2R9';
fixes['12.3']    = '12.3R7';
fixes['13.1']    = '13.1R4-S2';
fixes['13.3']    = '13.3R3';
fixes['14.1']    = '14.1R2';
fixes['14.2']    = '14.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# This isn't necessary, but is included in the advisory
if (fix == "12.1X44-D35")
  fix = "12.1X44-D35 or 12.1X44-D40";

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix);
  security_hole(port:0, extra:report);
}
else security_hole(0);
