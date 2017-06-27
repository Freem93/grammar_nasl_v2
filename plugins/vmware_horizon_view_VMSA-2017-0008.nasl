#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99708);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/04 16:16:17 $");

  script_cve_id("CVE-2017-4907");
  script_bugtraq_id(97914);
  script_osvdb_id(155969);
  script_xref(name:"VMSA", value:"2017-0008");
  script_xref(name:"IAVA", value:"2017-A-0128");

  script_name(english:"VMware Horizon View 6.x < 6.2.4 / 7.x < 7.1.0 Unspecified Buffer Overflow RCE (VMSA-2017-0008)");
  script_summary(english:"Checks the version of VMware Horizon View.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application installed on the remote Windows host is
affected by a remote code execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"The version of VMware Horizon View installed on the remote Windows
host is 6.x prior to 6.2.4 or 7.x prior to 7.1.0. It is, therefore,
affected by an unspecified heap buffer overflow condition that allows
an unauthenticated, remote attacker to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2017-0008.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware Horizon View version 6.2.4 / 7.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:horizon_view");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("vmware_horizon_view_installed.nbin");
  script_require_keys("installed_sw/VMware Horizon View");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"VMware Horizon View", win_local:TRUE);

constraints = [
  { "min_version" : "6", "fixed_version" : "6.2.4" },
  { "min_version" : "7", "fixed_version" : "7.1.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
