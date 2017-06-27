#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2011-0007. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(53592);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/11/30 14:45:01 $");

  script_cve_id("CVE-2010-1323", "CVE-2010-1324", "CVE-2010-2240", "CVE-2010-4020", "CVE-2010-4021", "CVE-2011-1785", "CVE-2011-1786");
  script_bugtraq_id(42505, 45116, 45117, 45118, 45122, 47625, 47627);
  script_osvdb_id(67237, 69607, 69608, 69609, 69610, 72118, 73742);
  script_xref(name:"VMSA", value:"2011-0007");
  script_xref(name:"IAVA", value:"2011-A-0066");

  script_name(english:"VMSA-2011-0007 : VMware ESXi and ESX Denial of Service and third-party updates for Likewise components and ESX Service Console");
  script_summary(english:"Checks esxupdate output for the patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote VMware ESXi / ESX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. ESX/ESXi Socket Exhaustion
 
 By sending malicious network traffic to an ESXi or ESX host an
 attacker could exhaust the available sockets which would prevent
 further connections to the host. In the event a host becomes
 inaccessible its virtual machines will continue to run and have
 network connectivity but a reboot of the ESXi or ESX host may be
 required in order to be able to connect to the host again.

 ESXi and ESX hosts may intermittently lose connectivity caused by
 applications that do not correctly close sockets. If this occurs an
 error message similar to the following may be written to the vpxa
 log :
 
     socket() returns -1 (Cannot allocate memory)

  An error message similar to the following may be written to the
  vmkernel logs :

     socreate(type=2, proto=17) failed with error 55

  VMware would like to thank Jimmy Scott at inet-solutions.be for
  reporting this issue to us.

  The Common Vulnerabilities and Exposures Project (cve.mitre.org) has
  assigned the name CVE-2011-1785 to this issue.

b. Likewise package update
 
  Updates to the vmware-esx-likewise-openldap and
  vmware-esx-likewise-krb5 packages address several security issues.

  One of the vulnerabilities is specific to Likewise while the other
  vulnerabilities are present in the MIT version of krb5.
  An incorrect assert() call in Likewise may lead to a termination
  of the Likewise-open lsassd service if a username with an illegal
  byte sequence is entered for user authentication when logging in to
  the Active Directory domain of the ESXi/ESX host. This would lead to
  a denial of service.
  The MIT-krb5 vulnerabilities are detailed in MITKRB5-SA-2010-007.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the names CVE-2011-1786 (Likewise-only issue),
  CVE-2010-1324, CVE-2010-1323, CVE-2010-4020, CVE-2010-4021 to these
  issues.

c. ESX third-party update for Service Console kernel
 
  The Service Console kernel is updated to include a fix for a
  security issue.
  
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2010-2240 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2011/000133.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/29");
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


init_esx_check(date:"2011-04-28");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201104401-SG",
    patch_updates : make_list("ESX400-201111201-SG", "ESX400-201203401-SG", "ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201104401-SG",
    patch_updates : make_list("ESX410-201110201-SG", "ESX410-201201401-SG", "ESX410-201204401-SG", "ESX410-201205401-SG", "ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201104401-SG",
    patch_updates : make_list("ESXi400-201110401-SG", "ESXi400-201203401-SG", "ESXi400-201205401-SG", "ESXi400-201206401-SG", "ESXi400-201209401-SG", "ESXi400-201302401-SG", "ESXi400-201305401-SG", "ESXi400-201310401-SG", "ESXi400-201404401-SG", "ESXi400-Update03", "ESXi400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201104401-SG",
    patch_updates : make_list("ESXi410-201110201-SG", "ESXi410-201201401-SG", "ESXi410-201204401-SG", "ESXi410-201205401-SG", "ESXi410-201206401-SG", "ESXi410-201208101-SG", "ESXi410-201211401-SG", "ESXi410-201301401-SG", "ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG", "ESXi410-Update02", "ESXi410-Update03")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
