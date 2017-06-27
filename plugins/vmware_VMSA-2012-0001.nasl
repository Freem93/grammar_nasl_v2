#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2012-0001. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(57749);
  script_version("$Revision: 1.32 $");
  script_cvs_date("$Date: 2016/11/30 14:45:01 $");

  script_cve_id("CVE-2009-3560", "CVE-2009-3720", "CVE-2010-0547", "CVE-2010-0787", "CVE-2010-1634", "CVE-2010-2059", "CVE-2010-2089", "CVE-2010-3493", "CVE-2010-4649", "CVE-2011-0695", "CVE-2011-0711", "CVE-2011-0726", "CVE-2011-1015", "CVE-2011-1044", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1093", "CVE-2011-1163", "CVE-2011-1166", "CVE-2011-1170", "CVE-2011-1171", "CVE-2011-1172", "CVE-2011-1182", "CVE-2011-1494", "CVE-2011-1495", "CVE-2011-1521", "CVE-2011-1573", "CVE-2011-1576", "CVE-2011-1577", "CVE-2011-1593", "CVE-2011-1678", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1763", "CVE-2011-1776", "CVE-2011-1780", "CVE-2011-1936", "CVE-2011-2022", "CVE-2011-2192", "CVE-2011-2213", "CVE-2011-2482", "CVE-2011-2491", "CVE-2011-2492", "CVE-2011-2495", "CVE-2011-2517", "CVE-2011-2519", "CVE-2011-2522", "CVE-2011-2525", "CVE-2011-2689", "CVE-2011-2694", "CVE-2011-2901", "CVE-2011-3378");
  script_bugtraq_id(36097, 37203, 37992, 38326, 40370, 40863, 44533, 46073, 46417, 46488, 46541, 46616, 46793, 46839, 46878, 46919, 47003, 47024, 47308, 47343, 47497, 47534, 47535, 47791, 47796, 47843, 48048, 48058, 48333, 48441, 48538, 48641, 48677, 48899, 48901, 49141, 49370, 49373, 49375, 49408, 49939);
  script_osvdb_id(59737, 60797, 62155, 62186, 64957, 65143, 65144, 65151, 68739, 70950, 71330, 71331, 71361, 71480, 71649, 71653, 71656, 71992, 72993, 73042, 73043, 73045, 73046, 73047, 73048, 73049, 73295, 73296, 73297, 73328, 73459, 73460, 73686, 73802, 73872, 73882, 74071, 74072, 74635, 74642, 74649, 74650, 74653, 74654, 74655, 74656, 74657, 74658, 74660, 74676, 74868, 74872, 74873, 75240, 75241, 75930, 75931);
  script_xref(name:"VMSA", value:"2012-0001");
  script_xref(name:"IAVA", value:"2012-A-0020");

  script_name(english:"VMSA-2012-0001 : VMware ESXi and ESX updates to third-party library and ESX Service Console");
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
"a. ESX third-party update for Service Console kernel
  
   The ESX Service Console Operating System (COS) kernel is updated to
   kernel-2.6.18-274.3.1.el5 to fix multiple security issues in the
   COS kernel.
  
   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2011-0726, CVE-2011-1078, CVE-2011-1079,
   CVE-2011-1080, CVE-2011-1093, CVE-2011-1163, CVE-2011-1166,
   CVE-2011-1170, CVE-2011-1171, CVE-2011-1172, CVE-2011-1494,
   CVE-2011-1495, CVE-2011-1577, CVE-2011-1763, CVE-2010-4649,
   CVE-2011-0695, CVE-2011-0711, CVE-2011-1044, CVE-2011-1182,
   CVE-2011-1573, CVE-2011-1576, CVE-2011-1593, CVE-2011-1745,
   CVE-2011-1746, CVE-2011-1776, CVE-2011-1936, CVE-2011-2022,
   CVE-2011-2213, CVE-2011-2492, CVE-2011-1780, CVE-2011-2525,
   CVE-2011-2689, CVE-2011-2482, CVE-2011-2491, CVE-2011-2495,
   CVE-2011-2517, CVE-2011-2519, CVE-2011-2901 to these issues.
  
b. ESX third-party update for Service Console cURL RPM
  
   The ESX Service Console (COS) curl RPM is updated to cURL-7.15.5.9
   resolving a security issues.
  
   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the name CVE-2011-2192 to this issue.
  
c. ESX third-party update for Service Console nspr and nss RPMs
  
   The ESX Service Console (COS) nspr and nss RPMs are updated to
   nspr-4.8.8-1.el5_7 and nss-3.12.10-4.el5_7 respectively resolving
   a security issues.
  
   A Certificate Authority (CA) issued fraudulent SSL certificates and
   Netscape Portable Runtime (NSPR) and Network Security Services (NSS)
   contain the built-in tokens of this fraudulent Certificate
   Authority. This update renders all SSL certificates signed by the
   fraudulent CA as untrusted for all uses.
  
d. ESX third-party update for Service Console rpm RPMs
  
   The ESX Service Console Operating System (COS) rpm packages are
   updated to popt-1.10.2.3-22.el5_7.2, rpm-4.4.2.3-22.el5_7.2,
   rpm-libs-4.4.2.3-22.el5_7.2 and rpm-python-4.4.2.3-22.el5_7.2
   which fixes multiple security issues.
  
   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2010-2059 and CVE-2011-3378 to these
   issues.
  
e. ESX third-party update for Service Console samba RPMs
  
   The ESX Service Console Operating System (COS) samba packages are
   updated to samba-client-3.0.33-3.29.el5_7.4,
   samba-common-3.0.33-3.29.el5_7.4 and
   libsmbclient-3.0.33-3.29.el5_7.4 which fixes multiple security
   issues in the Samba client.
  
   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2010-0547, CVE-2010-0787, CVE-2011-1678,
   CVE-2011-2522 and CVE-2011-2694 to these issues.
  
   Note that ESX does not include the Samba Web Administration Tool
   (SWAT) and therefore ESX COS is not affected by CVE-2011-2522 and
   CVE-2011-2694.
  
f. ESX third-party update for Service Console python package
  
   The ESX Service Console (COS) python package is updated to
   2.4.3-44 which fixes multiple security issues.
  
   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2009-3720, CVE-2010-3493, CVE-2011-1015 and
   CVE-2011-1521 to these issues.
  
g. ESXi update to third-party component python
  
   The python third-party library is updated to python 2.5.6 which
   fixes multiple security issues.
  
   The Common Vulnerabilities and Exposures project (cve.mitre.org) has
   assigned the names CVE-2009-3560, CVE-2009-3720, CVE-2010-1634,
   CVE-2010-2089, and CVE-2011-1521 to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2012/000170.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 59, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/31");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2012-01-30");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201203401-SG",
    patch_updates : make_list("ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG")
  )
) flag++;
if (esx_check(ver:"ESX 4.0", patch:"ESX400-201203402-SG")) flag++;
if (esx_check(ver:"ESX 4.0", patch:"ESX400-201203403-SG")) flag++;
if (esx_check(ver:"ESX 4.0", patch:"ESX400-201203404-SG")) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201203405-SG",
    patch_updates : make_list("ESX400-201209404-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201201401-SG",
    patch_updates : make_list("ESX410-201204401-SG", "ESX410-201205401-SG", "ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201201402-SG",
    patch_updates : make_list("ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201201404-SG",
    patch_updates : make_list("ESX410-201211405-SG", "ESX410-201307402-SG", "ESX410-201312403-SG", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201201405-SG",
    patch_updates : make_list("ESX410-201211407-SG", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201201406-SG",
    patch_updates : make_list("ESX410-201208105-SG", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201201407-SG",
    patch_updates : make_list("ESX410-Update03")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201203401-SG",
    patch_updates : make_list("ESXi400-201205401-SG", "ESXi400-201206401-SG", "ESXi400-201209401-SG", "ESXi400-201302401-SG", "ESXi400-201305401-SG", "ESXi400-201310401-SG", "ESXi400-201404401-SG")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201201401-SG",
    patch_updates : make_list("ESXi410-201204401-SG", "ESXi410-201205401-SG", "ESXi410-201206401-SG", "ESXi410-201208101-SG", "ESXi410-201211401-SG", "ESXi410-201301401-SG", "ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG", "ESXi410-Update03")
  )
) flag++;

if (esx_check(ver:"ESXi 5.0", vib:"VMware:esx-base:5.0.0-0.10.608089")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
