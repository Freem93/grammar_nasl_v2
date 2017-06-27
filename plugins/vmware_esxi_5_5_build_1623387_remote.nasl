#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83781);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/09 15:53:03 $");

  script_cve_id("CVE-2013-4332", "CVE-2013-5211");
  script_bugtraq_id(62324, 64692);
  script_osvdb_id(97246, 97247, 97248, 101576);
  script_xref(name:"CERT", value:"348126");
  script_xref(name:"VMSA", value:"2014-0002");

  script_name(english:"ESXi 5.5 < Build 1623387 Multiple Vulnerabilities (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.5 host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 5.5 prior to build 1623387. It
is, therefore, affected by multiple vulnerabilities :

  - Multiple integer overflow conditions exist in the
    bundled GNU C Library (glibc) due to improper validation
    of user-supplied input. A remote attacker can exploit
    these issues to cause a buffer overflow, resulting in a
    denial of service condition. (CVE-2013-4332)

  - A flaw exists in the monlist feature in NTP. A remote
    attacker can exploit this flaw, using a specially
    crafted packet to load the query function in monlist, to
    conduct a distributed denial of service attack.
    (CVE-2013-5211)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2014-0002.html");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2065826");
  script_set_attribute(attribute:"solution", value:
"Apply patch ESXi550-201403101-SG for ESXi 5.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:glibc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
if ("VMware ESXi 5.5" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.5");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) exit(1, 'Failed to extract the ESXi build number.');

build       = int(match[1]);
fixed_build = 1623387;

if (build < fixed_build)
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
