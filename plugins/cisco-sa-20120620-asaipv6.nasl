#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59716);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2012-3058");
  script_bugtraq_id(54106);
  script_osvdb_id(83101);
  script_xref(name:"CISCO-BUG-ID", value:"CSCua27134");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120620-asaipv6");

  script_name(english:"Cisco ASA 5500 Series DoS (cisco-sa-20120620-asaipv6)");
  script_summary(english:"Checks ASA version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote security device is missing a vendor-supplied security
patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Cisco ASA is missing a security patch and may be affected
by a denial of service vulnerability.  Processing unspecified IPv6
transit traffic can result in a device reload.  A remote, unauthenticated
attacker could exploit this to cause a denial of service."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120620-asaipv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9426169");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120620-asaipv6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/26");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_5500");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("cisco_func.inc");
include("audit.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');
ver = extract_asa_version(asa);
if (isnull(ver)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (model !~ '^55[0-9][0-9]')
  audit(AUDIT_HOST_NOT, 'ASA 5500');

# The advisory says:
#   This vulnerability was introduced in 8.4(2).
#   Versions prior to 8.4(2) are not affected by this vulnerability
# The call below should return TRUE for all 8.4 releases before 8.4(2)
if (check_asa_release(version:ver, patched:'8.4(2)'))
  audit(AUDIT_INST_VER_NOT_VULN, 'ASA', ver);

# compare the ASA version versus all patches.  The comparison is only made if the major versions match up
patches = make_list('8.4(4.1)', '8.5(1.11)', '8.6(1.3)');
foreach patch (patches)
{
  if (check_asa_release(version:ver, patched:patch))
  {
    report =
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : ' + patch + '\n';
    security_hole(port:0, extra:report);
    exit(0);
  }
}

audit(AUDIT_INST_VER_NOT_VULN, 'ASA', ver);
