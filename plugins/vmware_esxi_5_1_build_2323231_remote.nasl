#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80037);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/09 15:53:03 $");

  script_cve_id("CVE-2013-0242", "CVE-2013-1914");
  script_bugtraq_id(57638, 58839);
  script_osvdb_id(89747, 92038);
  script_xref(name:"VMSA", value:"2014-0008");

  script_name(english:"ESXi 5.1 < Build 2323231 glibc Library Multiple Vulnerabilities (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.1 host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 5.1 prior to build 2323231. It
is, therefore, affected by the following vulnerabilities in the glibc
library :

  - A buffer overflow flaw exists in the 'extend_buffers'
    function of the 'posix/regexec.c' file due to improper
    validation of user input. Using a specially crafted
    expression, a remote attacker can cause a denial of
    service. (CVE-2013-0242)

  - A buffer overflow flaw exists in the 'getaddrinfo'
    function of the '/sysdeps/posix/getaddrinfo.c' file
    due to improper validation of user input. A remote
    attacker can cause a denial of service by triggering
    a large number of domain conversions. (CVE-2013-1914)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2014-0008.html");
  script_set_attribute(attribute:"solution", value:"Apply patch ESXi510-201412101-SG for ESXi 5.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2014-2016 Tenable Network Security, Inc.");
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
if ("VMware ESXi 5.1" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.1");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) exit(1, 'Failed to extract the ESXi build number.');

build       = int(match[1]);
fixed_build = 2323231;

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
