#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100423);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/25 21:38:04 $");

  script_cve_id("CVE-2017-3885", "CVE-2017-3887");
  script_bugtraq_id(97451, 97453);
  script_osvdb_id(155022, 155032);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc58563");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvb62292");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170405-cfpw");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170405-cfpw1");

  script_name(english:"Cisco Firepower Detection Engine SSL Multiple DoS (cisco-sa-20170405-cfpw) (cisco-sa-20170405-cfpw1)");
  script_summary(english:"Checks the version of Cisco Firepower System.");

  script_set_attribute(attribute:"synopsis", value:
"The packet inspection software installed on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Cisco Firepower Threat Defense (FTD)
software installed on the remote device is prior to 6.1.0.2 or else is
6.2.x prior to 6.2.0.1. It is, therefore, affected by multiple
vulnerabilities :

  - A denial of service vulnerability exists in the
    detection engine reassembly of Secure Sockets Layer
    (SSL) packets due to improper handling of an SSL packet
    stream. An unauthenticated, remote attacker can exploit
    this, via a crafted SSL packet stream, to cause the
    Snort process to consume a high level of CPU resources.
    (CVE-2017-3885)

  - A denial of service vulnerability exists in the
    detection engine due to improper handling of an SSL
    packet in an established SSL connection. An
    unauthenticated, remote attacker can exploit this, via a
    crafted SSL packet stream, to cause the Snort process to
    restart, allowing traffic inspection to be bypassed or
    traffic to be dropped. (CVE-2017-3887)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-cfpw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6debfa41");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-cfpw1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bc33ad5");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc58563");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc58563");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvc58563 and CSCvb62292.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/05");
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

else if (fdm_ver[1] =~ "^6\.2\.")
  fix = '6.2.0.1';
else
  fix = '6.1.0.2';

if (fix && (ver_compare(ver:fdm_ver[1], fix:fix, strict:FALSE) < 0))
{
  report =
    '\n  Bug               : CSCvc58563 and CSCvb62292' +
    '\n  Installed version : ' + fdm_ver[1] +
    '\n  Fixed version     : ' + fix;
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
} else audit(AUDIT_HOST_NOT, "affected");
