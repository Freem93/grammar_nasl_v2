#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2013-0009. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(69193);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id("CVE-2013-0166", "CVE-2013-0169", "CVE-2013-0268", "CVE-2013-0338", "CVE-2013-0871", "CVE-2013-2116");
  script_bugtraq_id(57778, 57838, 57986, 58180, 60215, 60268);
  script_osvdb_id(89848, 89865, 90003, 90301, 90631, 93743);
  script_xref(name:"VMSA", value:"2013-0009");

  script_name(english:"VMSA-2013-0009 : VMware vSphere, ESX and ESXi updates to third-party libraries");
  script_summary(english:"Checks esxupdate output for the patches");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote VMware ESXi / ESX host is missing one or more
security-related patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. vCenter Server and ESX userworld update for OpenSSL library

   The userworld OpenSSL library is updated to version openssl-0.9.8y
   to resolve multiple security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2013-0169 and CVE-2013-0166 to these
   issues.

b. Service Console (COS) update for OpenSSL library

   The Service Console updates for OpenSSL library is updated to version
   openssl-0.9.8e-26.el5_9.1 to resolve multiple security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2013-0169 and CVE-2013-0166 to these
   issues.

c. ESX Userworld and Service Console (COS) update for libxml2 library 

   The ESX Userworld and Service Console libxml2 library is updated to
   version libxml2-2.6.26-2.1.21.el5_9.1 and 
   libxml2-python-2.6.26-2.1.21.el5_9.1. to resolve a security issue.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2013-0338 to this issue.

d. Service Console (COS) update for GnuTLS library 

   The ESX service console GnuTLS RPM is updated to version
   gnutls-1.4.1-10.el5_9.1 to resolve a security issue.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2013-2116 to this issue.

e. ESX third-party update for Service Console kernel 

   The ESX Service Console Operating System (COS) kernel is updated 
   to kernel-2.6.18-348.3.1.el5 which addresses several security
   issues in the COS kernel. 

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2013-0268 and CVE-2013-0871 to these
   issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2014/000230.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2013-07-31");
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
    patch         : "ESX410-201307401-SG",
    patch_updates : make_list("ESX410-201312401-SG", "ESX410-201404401-SG")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201307402-SG",
    patch_updates : make_list("ESX410-201312403-SG")
  )
) flag++;
if (esx_check(ver:"ESX 4.1", patch:"ESX410-201307403-SG")) flag++;
if (esx_check(ver:"ESX 4.1", patch:"ESX410-201307404-SG")) flag++;
if (esx_check(ver:"ESX 4.1", patch:"ESX410-201307405-SG")) flag++;

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
    patch         : "ESXi410-201307401-SG",
    patch_updates : make_list("ESXi410-201312401-SG", "ESXi410-201404401-SG")
  )
) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-2.38.1311177")) flag++;
if (esx_check(ver:"ESXi 5.0", vib:"VMware:misc-drivers:5.0.0-2.38.1311177")) flag++;
if (esx_check(ver:"ESXi 5.0", vib:"VMware:net-bnx2x:1.61.15.v50.1-2vmw.500.2.38.1311177")) flag++;

if (esx_check(ver:"ESXi 5.1", vib:"VMware:esx-base:5.1.0-1.22.1472666")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:esx_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
