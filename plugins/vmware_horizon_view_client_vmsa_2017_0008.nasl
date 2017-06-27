#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99709);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/04 16:16:17 $");

  script_cve_id(
    "CVE-2017-4908",
    "CVE-2017-4909",
    "CVE-2017-4910",
    "CVE-2017-4911",
    "CVE-2017-4912",
    "CVE-2017-4913"
  );
  script_bugtraq_id(
    97911,
    97912,
    97913,
    97916,
    97920,
    97921
  );
  script_osvdb_id(
    155970,
    155971,
    155977,
    155978,
    155979,
    155980,
    155981
  );
  script_xref(name:"VMSA", value:"2017-0008");
  script_xref(name:"IAVA", value:"2017-A-0127");

  script_name(english:"VMware Horizon View Client 4.x < 4.4.0 Multiple Vulnerabilities (VMSA-2017-0008)");
  script_summary(english:"Checks the VMware Horizon View Client version.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Horizon View Client installed on the remote host
is 4.x prior to 4.4.0. It is, therefore, affected by multiple
vulnerabilities :

  - A heap buffer overflow condition exists in the Cortado
    ThinPrint component, specifically within TPView.dll,
    due to improper validation of certain input when parsing
    JPEG2000 files. An attacker on the guest can exploit
    this to cause a denial of service condition or the
    execution or arbitrary code on the host system.
    (CVE-2017-4908)

  - A heap buffer overflow condition exists in the Cortado
    ThinPrint component, specifically within TPView.dll,
    due to improper validation of certain input when parsing
    TrueType Fonts. An attacker on the guest can exploit
    this to cause a denial of service condition or the
    execution or arbitrary code on the host system.
    (CVE-2017-4909)

  - Out-of-bounds read and write errors exist in the Cortado
    ThinPrint component, specifically within TPView.dll,
    due to improper validation of certain input when parsing
    JPEG2000 files. An attacker on the guest can exploit
    these to corrupt memory, resulting in a denial of
    service condition or the execution of arbitrary code on
    the host system. (CVE-2017-4910, CVE-2017-4911)

  - Out-of-bounds read and write errors exist in the Cortado
    ThinPrint component, specifically within TPView.dll,
    due to improper validation of certain input when parsing
    TrueType Fonts. An attacker on the guest can exploit
    these to corrupt memory, resulting in a denial of service
    condition or the execution of arbitrary code on the host
    system. (CVE-2017-4912)

  - An integer overflow condition exists in the Cortado
    ThinPrint component, specifically within TPView.dll,
    due to improper validation of certain input when parsing
    TrueType Fonts. An attacker on the guest can exploit
    this to corrupt memory, resulting in a denial of service
    condition or the execution of arbitrary code on the host
    system. (CVE-2017-4913)

The above vulnerabilities can be exploited only if virtual printing
has been enabled. This feature is enabled by default on VMware Horizon
View.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2017-0008");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Horizon View Client 4.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("vmware_horizon_view_client_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/VMware Horizon View Client");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"VMware Horizon View Client", win_local:TRUE);

constraints = [{ "min_version" : "4", "fixed_version" : "4.4.0" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
