#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100424);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/25 21:38:04 $");

  script_cve_id("CVE-2016-6368");
  script_bugtraq_id(97932);
  script_osvdb_id(155948);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuz00876");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170201-fpsnort");

  script_name(english:"Cisco Firepower Detection Engine Pragmatic General Multicast Protocol Decoding DoS (cisco-sa-20170419-fpsnort)");
  script_summary(english:"Checks the version of Cisco Firepower System.");

  script_set_attribute(attribute:"synopsis", value:
"The packet inspection software installed on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Cisco Firepower Threat Defense (FTD)
software installed on the remote host is 5.4.0.x prior to 5.4.0.10,
5.4.1.x prior to 5.4.1.9, or 6.0.1.x prior to either 6.0.1.3, 6.1.0,
or 6.2.0. It is, therefore, affected by a denial of service
vulnerability in the packet detection and inspection engine due to
improper validation of fields in Pragmatic General Multicast (PGM)
protocol packets. An unauthenticated, remote attacker can exploit
this, via a specially crafted PGM protocol packet, to cause the Snort
process to restart, allowing traffic inspection to be bypassed or
traffic to be dropped.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170419-fpsnort
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17047a21");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuz00876.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:firepower_threat_defense");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

show_ver = get_kb_item_or_exit('Host/Cisco/show_ver');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

# Affected Models:
# 5500-X Series
if (
  model !~ '^55[0-9][0-9][WH]?-X'
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product model");

fix = NULL;
override = 0;

fdm_ver = pregmatch(string:show_ver, pattern:"\s*Model\s*:\s+Cisco.*Threat\s+Defense.*Version\s+([0-9.]+)");

if (isnull(fdm_ver)) audit(AUDIT_HOST_NOT, "affected");

if (fdm_ver[1] =~ "^5\.4\.0\.")
  fix = '5.4.0.10';
else if (fdm_ver[1] =~ "^5\.4\.1\.")
  fix = '5.4.1.9';
else if (fdm_ver[1] =~ "^6\.0\.1\.")
  fix = '6.0.1.3';
else if (fdm_ver[1] =~ "^6\.1\.")
  fix = '6.1.0';
else
  fix = '6.2.0';

if (fix && (ver_compare(ver:fdm_ver[1], fix:fix, strict:FALSE) < 0))
{
  report =
    '\n  Bug               : CSCuz00876' +
    '\n  Installed version : ' + fdm_ver[1] +
    '\n  Fixed version     : ' + fix;
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
} else audit(AUDIT_HOST_NOT, "affected");
