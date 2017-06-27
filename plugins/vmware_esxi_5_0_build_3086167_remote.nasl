#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(87940);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id("CVE-2015-6933");
  script_osvdb_id(132670);
  script_xref(name:"VMSA", value:"2016-0001");
  script_xref(name:"IAVB", value:"2016-B-0013");

  script_name(english:"ESXi 5.0 < Build 3086167 Shared Folders (HGFS) Guest Privilege Escalation (VMSA-2016-0001) (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.0 host is affected by a guest privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi 5.0 host is prior to build 3086167. It is,
therefore, affected by a guest privilege escalation vulnerability in
the Shared Folders (HGFS) feature due to improper validation of
user-supplied input. A local attacker can exploit this to corrupt
memory, resulting in an elevation of privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2016-0001.html");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2120210");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2113684");
  script_set_attribute(attribute:"solution", value:
"Apply patch ESXi500-201510102-SG according to the vendor advisory.

Note that VMware Tools in any Windows-based guests that use the Shared
Folders (HGFS) feature must also be updated to completely mitigate the
vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");

if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");
if ("VMware ESXi 5.0" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.0");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, "VMware ESXi", "5.0");

build = int(match[1]);
fixed_build = 3086167;
security_only_build = 3021432;

if (build < fixed_build && build != security_only_build)
{
  if (report_verbosity > 0)
  {
    report = '\n  ESXi version    : ' + ver +
             '\n  Installed build : ' + build +
             '\n  Fixed build     : ' + fixed_build +
             '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "VMware ESXi", ver - "ESXi " + " build " + build);
