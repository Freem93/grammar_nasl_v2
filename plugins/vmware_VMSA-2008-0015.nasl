#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2008-0015. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(52010);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2008-2234");
  script_osvdb_id(47534);
  script_xref(name:"VMSA", value:"2008-0015");
  script_xref(name:"IAVB", value:"2008-B-0064");

  script_name(english:"VMSA-2008-0015 : Updated ESXi and ESX 3.5 packages address critical security issue in openwsman");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a.  Updated Openwsman

  Openwsman is a system management platform that implements the Web
  Services Management protocol (WS-Management). It is installed and
  running by default. It is used in the VMware Management Service
  Console and in ESXi.

  The openwsman 2.0.0 management service on ESX 3.5 and ESXi 3.5 is
  vulnerable to the following issue found by the SuSE Security-Team :

  - Two remote buffer overflows while decoding the HTTP basic
    authentication header

  This vulnerability could potentially be exploited by users without
  valid login credentials.
 
  Openwsman before 2.0.0 is not vulnerable to this issue. The ESXi
  3.5 patch ESXe350-200808201-O-UG updated openwsman to version 2.0.0.
  The ESX 3.5 patch ESX350-200808205-UG updated openwsman to version
  2.0.0. These patches are installed as part of the ESX and ESXi
  Upgrade 2 release. The ESX patch can be installed individually.

  Version Information and Workaround
  The following VMware KB articles provide information on how to
  obtain the version of openwsman in your environment and what a
  possible workaround for the issue might be.
  ESXi 3.5
    Refer to the VMware KB article at http://kb.vmware.com/kb/1005818.
  ESX 3.5
    Refer to the VMware KB article at http://kb.vmware.com/kb/1006878.

  Note: This vulnerability can be exploited remotely only if the
        attacker has access to the service console network.
        Security best practices provided by VMware recommend that the
        service console be isolated from the VM network. Please see
        http://www.vmware.com/resources/techresources/726 for more
        information on VMware security best practices.

  The Common Vulnerabilities and Exposures Project (cve.mitre.org)
  has assigned the name CVE-2008-2234 this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2008/000034.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:3.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/17");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"VMware ESX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/VMware/release", "Host/VMware/version");
  script_require_ports("Host/VMware/esxupdate", "Host/VMware/esxcli_software_vibs");

  exit(0);
}


include("audit.inc");
include("vmware_esx_packages.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/VMware/release")) audit(AUDIT_OS_NOT, "VMware ESX / ESXi");
if (
  !get_kb_item("Host/VMware/esxcli_software_vibs") &&
  !get_kb_item("Host/VMware/esxupdate")
) audit(AUDIT_PACKAGE_LIST_MISSING);


init_esx_check(date:"2008-09-18");
flag = 0;


if (esx_check(ver:"ESXi 3.5.0", patch:"ESXe350-200808501-I-SG")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
