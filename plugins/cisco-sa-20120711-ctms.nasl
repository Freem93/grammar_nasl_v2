#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70024);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/09/22 00:07:26 $");

  script_cve_id("CVE-2012-2486", "CVE-2012-3073");
  script_bugtraq_id(54382);
  script_osvdb_id(83715, 83731);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120711-ctms");
  script_xref(name:"IAVB", value:"2012-B-0070");

  script_name(english:"Cisco TelePresence Multipoint Switch Multiple Vulnerabilities (cisco-sa-20120711-ctms)");
  script_summary(english:"Checks CTMS version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version, the version of Cisco
TelePresence Multipoint Switch Server installed on the remote host is
potentially affected by multiple vulnerabilities :

  - By sending specially crafted IP packets at a high rate,
    it may be possible to crash some of the services running
    on the host. (CVE-2012-3073)

  - The Cisco Discovery Protocol (CDP) implementation on the
    remote host is affected by a vulnerability that could
    allow a remote, unauthenticated, adjacent attacker with
    data link layer access the ability to execute arbitrary
    code by sending specially crafted CDP packets.
    (CVE-2012-2486)"
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120711-ctms
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c6411aa");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Cisco TelePresence Multipoint Switch 1.9.0 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_multipoint_switch_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/UCOS/Cisco TelePresence Multipoint Switch/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

display_version = get_kb_item_or_exit('Host/UCOS/Cisco TelePresence Multipoint Switch/version');
match = eregmatch(string:display_version, pattern:'^([0-9.]+)');
if (isnull(match)) # this should not happen
  audit(AUDIT_FN_FAIL, 'eregmatch');
else
  version = match[1];

# versions prior to 1.9.0 are vulnerable
if (ver_compare(ver:version, fix:'1.9', strict:FALSE) == -1)
  fix = '1.9.0';
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco TelePresence Multipoint Switch', display_version);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + display_version +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
