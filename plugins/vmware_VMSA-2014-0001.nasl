#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2014-0001. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(72006);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2014-1207", "CVE-2014-1208", "CVE-2014-1211");
  script_bugtraq_id(64993, 64994, 64995);
  script_osvdb_id(102196, 102197, 102198);
  script_xref(name:"VMSA", value:"2014-0001");
  script_xref(name:"IAVA", value:"2013-A-0205");
  script_xref(name:"IAVB", value:"2014-B-0008");
  script_xref(name:"IAVB", value:"2014-B-0009");
  script_xref(name:"IAVB", value:"2014-B-0010");

  script_name(english:"VMSA-2014-0001 : VMware Workstation, Player, Fusion, ESXi, ESX and vCloud Director address several security issues");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi / ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. VMware ESXi and ESX NFC NULL pointer dereference

      VMware ESXi and ESX contain a NULL pointer dereference in 
      the handling of the Network File Copy (NFC) traffic. To 
      exploit this vulnerability, an attacker must intercept and
      modify the NFC traffic between ESXi/ESX and the client.  
      Exploitation of the issue may lead to a Denial of Service.

      To reduce the likelihood of exploitation, vSphere components  
      should be deployed on an isolated management network.
     
      VMware would like to thank Alex Chapman of Context Information
      Security for reporting this issue to us.

      The Common Vulnerabilities and Exposures project (cve.mitre.org) has
      assigned the name CVE-2014-1207 to this issue.

b. VMware VMX process denial of service vulnerability

      Due to a flaw in the handling of invalid ports, it is possible 
      to cause the VMX process to fail. This vulnerability may allow a 
      guest user to affect the VMX process resulting in a partial denial of
      service on the host.

      VMware would like to thank Recurity Labs GmbH and the Bundesamt 
      Sicherheit in der Informationstechnik (BSI) for reporting this 
      issue to us

      The Common Vulnerabilities and Exposures project (cve.mitre.org) has
      assigned the name CVE-2014-1208 to this issue.

c. VMware vCloud Director Cross Site Request Forgery (CSRF)

      VMware vCloud Director contains a vulnerability in the Hyper Text
Transfer
      Protocol (http) session management. An attacker may trick an
authenticated 
      user to click a malicious link, which would result in the user being
logged
      out. The user is able to immediately log back into the system. 

      VMware would like to thank Mattia Folador for reporting this issue to
us.

      The Common Vulnerabilities and Exposures project (cve.mitre.org) has
      assigned the name CVE-2014-1211 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2014/000231.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/17");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2014-01-16");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201310401-SG",
    patch_updates : make_list("ESX400-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201312401-SG",
    patch_updates : make_list("ESX410-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201310401-SG",
    patch_updates : make_list("ESXi400-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201312401-SG",
    patch_updates : make_list("ESXi410-201404401-SG")
  )
) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-2.38.1311177")) flag++;

if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-base:5.1.0-1.22.1472666")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
