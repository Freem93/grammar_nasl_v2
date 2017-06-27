#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89035);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/03/01 14:49:47 $");

  script_cve_id(
    "CVE-2012-1516",
    "CVE-2012-1517",
    "CVE-2012-2448",
    "CVE-2012-2449",
    "CVE-2012-2450"
  );
  script_bugtraq_id(53369, 53371);
  script_osvdb_id(
    81691,
    81692,
    81693,
    81694,
    81695
  );
  script_xref(name:"VMSA", value:"2012-0009");

  script_name(english:"VMware ESX / ESXi Multiple Vulnerabilities (VMSA-2012-0009) (remote check)");
  script_summary(english:"Checks the ESX / ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESX / ESXi host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESX / ESXi host is affected by multiple
vulnerabilities :

  - Multiple privilege escalation vulnerabilities exist due
    to improper handling of RPC commands. A local attacker
    (guest user) can exploit these to manipulate data and
    function pointers, resulting in a denial of service
    condition or the execution of arbitrary code on the host
    OS. (CVE-2012-1516, CVE-2012-1517)

  - A remote code execution vulnerability exists due to
    improper sanitization of user-supplied input when
    parsing NFS traffic. An unauthenticated, remote attacker
    can exploit this to corrupt memory, resulting in the
    execution of arbitrary code. (CVE-2012-2448)

  - Multiple privilege escalation vulnerabilities exist due
    to an error that occurs in virtual floppy devices and
    SCSI devices. A local attacker (guest user) can exploit
    these to cause an out-of-bounds write error, resulting
    in a denial of service condition or the execution of
    arbitrary code on the host OS. (CVE-2012-2449,
    CVE-2012-2450)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0009.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory that
pertains to ESX version 3.5 / 4.0 / 4.1 or ESXi version 3.5 / 4.0 /
4.1 / 5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");
  script_require_ports("Host/VMware/vsphere");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/VMware/version");
release = get_kb_item_or_exit("Host/VMware/release");
port    = get_kb_item_or_exit("Host/VMware/vsphere");

# Version + build map
# https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=1014508
fixes = make_array();
# https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2019536
fixes["ESX 3.5"]  = 702112;
# https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2019538
fixes["ESXi 3.5"] = 702112;
fixes["ESX 4.0"]  = 702116;
fixes["ESXi 4.0"] = 702116;
fixes["ESX 4.1"]  = 702113;
fixes["ESXi 4.1"] = 702113;
fixes["ESXi 5.0"] = 702118;

matches = eregmatch(pattern:'^VMware (ESXi?).*build-([0-9]+)$', string:release);
if (empty_or_null(matches))
  exit(1, 'Failed to extract the ESX / ESXi build number.');

type  = matches[1];
build = int(matches[2]);

fixed_build = fixes[version];

if (!isnull(fixed_build) && build < fixed_build)
{
  padding = crap(data:" ", length:8 - strlen(type)); # Spacing alignment
 
  report = '\n  ' + type + ' version' + padding + ': ' + version +
           '\n  Installed build : ' + build +
           '\n  Fixed build     : ' + fixed_build +
           '\n';

  security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "VMware " + version + " build " + build);
