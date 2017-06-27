#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81084);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/05/22 16:17:18 $");

  script_cve_id("CVE-2013-5211", "CVE-2014-8370", "CVE-2015-1044");
  script_bugtraq_id(64692, 72336, 72338);
  script_osvdb_id(101576, 117669, 117671);
  script_xref(name:"CERT", value:"348126");
  script_xref(name:"VMSA", value:"2014-0002");
  script_xref(name:"VMSA", value:"2015-0001");

  script_name(english:"ESXi 5.1 < Build 1743201 Multiple Vulnerabilities (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.1 host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 5.1 prior to build 1743201. It
is, therefore, affected by multiple vulnerabilities :

  - A flaw exists in the monlist feature in NTP. A remote
    attacker can exploit this flaw, using a specially
    crafted packet to load the query function in monlist, to
    conduct a distributed denial of service attack.
    (CVE-2013-5211)

  - An unspecified privilege escalation vulnerability exists
    that allows an attacker to gain host OS privileges or
    cause a denial of service condition by modifying a
    configuration file. (CVE-2014-8370)

  - A flaw exists in the VMware Authorization process
    (vmware-authd) due to improper validation of
    user-supplied input. A remote attacker can exploit this
    to cause a denial of service condition. (CVE-2015-1044)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0002.html");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0001.html");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2070666");
  script_set_attribute(attribute:"solution", value:
"Apply patch ESXi510-201404001 for ESXi 5.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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
if ("VMware ESXi 5.1" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.1");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) exit(1, 'Failed to extract the ESXi build number.');

build = int(match[1]);
fixed_build = 1743201;

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
