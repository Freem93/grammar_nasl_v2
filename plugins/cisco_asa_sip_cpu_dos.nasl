#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(61514);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/02/05 16:07:42 $");

  script_cve_id("CVE-2012-2472");
  script_bugtraq_id(54836);
  script_osvdb_id(84509);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz63143");

  script_name(english:"Cisco ASA SIP CPU Utilization DoS");
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
by a denial of service vulnerability.  When SIP inspection is enabled
and SIP traffic does not establish the secondary connection, duplicate
pre-allocated secondary pinholes are created, which could cause CPU
utilization to increase.  A remote, unauthenticated attacker could
exploit this to cause a denial of service."
  );
  # http://tools.cisco.com/Support/BugToolKit/search/getBugDetails.do?method=fetchBugDetails&bugId=CSCtz63143
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8bc857b4");
  script_set_attribute(
    attribute:"solution",
    value:"Apply the relevant patch referenced in the bug details for CSCtz63143."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:asa_5500");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:5500_series_adaptive_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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

# compare the ASA version versus all recommended releases.  The comparison is only made if the major versions match up
recommended_releases = make_list('8.2(5.30)', '8.4(4.2)', '8.5(1.11)', '8.6(1.3)');
foreach patch (recommended_releases)
{
  if (check_asa_release(version:ver, patched:patch))
  {
    report =
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : ' + patch + '\n';
    security_warning(port:0, extra:report);
    exit(0);
  }
}

audit(AUDIT_INST_VER_NOT_VULN, 'ASA', ver);
