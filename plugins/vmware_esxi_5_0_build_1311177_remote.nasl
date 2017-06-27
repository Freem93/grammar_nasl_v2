#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70879);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id(
    "CVE-2013-0166",
    "CVE-2013-0169",
    "CVE-2013-0338",
    "CVE-2013-5970",
    "CVE-2013-5973",
    "CVE-2014-1207",
    "CVE-2014-1208"
  );
  script_bugtraq_id(
    57778,
    58180,
    60268,
    63216,
    64491,
    64994,
    64995
  );
  script_osvdb_id(
    89848,
    89865,
    90631,
    98719,
    101387,
    102196,
    102197
  );
  script_xref(name:"VMSA", value:"2013-0009");
  script_xref(name:"IAVA", value:"2013-A-0204");
  script_xref(name:"IAVA", value:"2013-A-0205");
  script_xref(name:"VMSA", value:"2013-0012");
  script_xref(name:"VMSA", value:"2013-0016");
  script_xref(name:"VMSA", value:"2014-0001");
  

  script_name(english:"ESXi 5.0 < Build 1311175 Multiple Vulnerabilities (remote check)");
  script_summary(english:"Checks ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.0 host is affected by multiple security
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi 5.0 host is affected by the following security
vulnerabilities :

  - Multiple errors exist related to OpenSSL that could
    allow information disclosure or denial of service
    attacks. (CVE-2013-0166, CVE-2013-0169)

  - An error exists in the libxml2 library related to the
    expansion of XML internal entities. An attacker can
    exploit this to cause a denial of service. (CVE-2013-0338)

  - An unspecified error exists related to 'hostd-vmdb'. An
    attacker can exploit this to cause a denial of service.
    (CVE-2013-5970)

  - An error exists in the handling of certain Virtual
    Machine file descriptors. This may allow an unprivileged
    user with the 'Add Existing Disk' privilege to obtain
    read and write access to arbitrary files, possibly
    leading to arbitrary code execution after a host reboot.
    (CVE-2013-5973)

  - A NULL pointer dereference flaw exists in the handling
    of Network File Copy (NFC) traffic. This issue may lead
    to a denial of service if an attacker intercepts and
    modifies the NFC traffic. (CVE-2014-1207)

  - A denial of service vulnerability exists in the handling
    of invalid ports that could allow a guest user to crash
    the VMX process. (CVE-2014-1208)");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2055559");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2013-0009.html");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2013-0012.html");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2013-0016.html");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2014-0001.html");
  script_set_attribute(attribute:"solution", value:
"Apply patch ESXi500-201310101-SG, ESXi500-201310201-UG, or
ESXi500-Update03.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

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
if (isnull(match)) exit(1, 'Failed to extract the ESXi build number.');

build = int(match[1]);
fixed_build = 1311175;

if (build < fixed_build)
{
  if (report_verbosity > 0)
  {
    report = '\n  ESXi version    : ' + ver +
             '\n  Installed build : ' + build +
             '\n  Fixed build     : ' + fixed_build +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host has "+ver+" build "+build+" and thus is not affected.");
