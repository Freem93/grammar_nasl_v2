#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2011-0013. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(56665);
  script_version("$Revision: 1.44 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2008-7270", "CVE-2010-1321", "CVE-2010-2054", "CVE-2010-3170", "CVE-2010-3173", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3550", "CVE-2010-3551", "CVE-2010-3552", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3555", "CVE-2010-3556", "CVE-2010-3557", "CVE-2010-3558", "CVE-2010-3559", "CVE-2010-3560", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3563", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3570", "CVE-2010-3571", "CVE-2010-3572", "CVE-2010-3573", "CVE-2010-3574", "CVE-2010-4180", "CVE-2010-4422", "CVE-2010-4447", "CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4451", "CVE-2010-4452", "CVE-2010-4454", "CVE-2010-4462", "CVE-2010-4463", "CVE-2010-4465", "CVE-2010-4466", "CVE-2010-4467", "CVE-2010-4468", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4471", "CVE-2010-4472", "CVE-2010-4473", "CVE-2010-4474", "CVE-2010-4475", "CVE-2010-4476", "CVE-2011-0002", "CVE-2011-0802", "CVE-2011-0814", "CVE-2011-0815", "CVE-2011-0862", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0871", "CVE-2011-0873");
  script_bugtraq_id(40235, 40475, 42817, 43965, 43971, 43979, 43985, 43988, 43992, 43994, 43999, 44009, 44011, 44012, 44013, 44014, 44016, 44017, 44020, 44021, 44023, 44024, 44026, 44027, 44028, 44030, 44032, 44035, 44038, 44040, 45164, 45254, 45791, 46091, 46386, 46387, 46388, 46391, 46393, 46394, 46395, 46397, 46398, 46399, 46400, 46402, 46403, 46404, 46405, 46406, 46407, 46409, 46410, 46411, 48137, 48139, 48142, 48143, 48144, 48145, 48147, 48148, 48149);
  script_osvdb_id(64744, 65157, 68079, 68844, 68873, 69033, 69034, 69035, 69036, 69037, 69038, 69039, 69040, 69041, 69042, 69043, 69044, 69045, 69046, 69047, 69048, 69049, 69050, 69051, 69052, 69053, 69055, 69056, 69057, 69058, 69059, 69565, 69655, 70083, 70421, 70965, 71193, 71605, 71606, 71607, 71608, 71609, 71610, 71611, 71612, 71613, 71614, 71615, 71616, 71617, 71618, 71619, 71620, 71621, 71622, 71623, 73069, 73070, 73071, 73074, 73075, 73076, 73077, 73083, 73085, 73176);
  script_xref(name:"VMSA", value:"2011-0013");
  script_xref(name:"IAVA", value:"2011-A-0160");
  script_xref(name:"IAVA", value:"2011-A-0173");

  script_name(english:"VMSA-2011-0013 : VMware third-party component updates for VMware vCenter Server, vCenter Update Manager, ESXi and ESX");
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
"a. ESX third-party update for Service Console openssl RPM

   The Service Console openssl RPM is updated to
   openssl-0.9.8e.12.el5_5.7 resolving two security issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2008-7270 and CVE-2010-4180 to these
   issues.
   
b. ESX third-party update for Service Console libuser RPM
 
   The Service Console libuser RPM is updated to version
   0.54.7-2.1.el5_5.2 to resolve a security issue.
  
   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2011-0002 to this issue.
  
c. ESX third-party update for Service Console nss and nspr RPMs
 
   The Service Console Network Security Services (NSS) and Netscape
   Portable Runtime (NSPR) libraries are updated to nspr-4.8.6-1
   and nss-3.12.8-4 resolving multiple security issues.
  
   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2010-3170 and CVE-2010-3173 to these
   issues.
  
d. vCenter Server and ESX, Oracle (Sun) JRE update 1.6.0_24

   Oracle (Sun) JRE is updated to version 1.6.0_24, which addresses
   multiple security issues that existed in earlier releases of
   Oracle (Sun) JRE.
  
   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the following names to the security issues fixed in
   JRE 1.6.0_24: CVE-2010-4422, CVE-2010-4447, CVE-2010-4448,
   CVE-2010-4450, CVE-2010-4451, CVE-2010-4452, CVE-2010-4454,
   CVE-2010-4462, CVE-2010-4463, CVE-2010-4465, CVE-2010-4466,
   CVE-2010-4467, CVE-2010-4468, CVE-2010-4469, CVE-2010-4470,
   CVE-2010-4471, CVE-2010-4472, CVE-2010-4473, CVE-2010-4474,
   CVE-2010-4475 and CVE-2010-4476.
  
   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the following names to the security issues fixed in
   JRE 1.6.0_22: CVE-2010-1321, CVE-2010-3541, CVE-2010-3548,
   CVE-2010-3549, CVE-2010-3550, CVE-2010-3551, CVE-2010-3552,
   CVE-2010-3553, CVE-2010-3554, CVE-2010-3555, CVE-2010-3556,
   CVE-2010-3557, CVE-2010-3558, CVE-2010-3559, CVE-2010-3560,
   CVE-2010-3561, CVE-2010-3562, CVE-2010-3563, CVE-2010-3565,
   CVE-2010-3566, CVE-2010-3567, CVE-2010-3568, CVE-2010-3569,
   CVE-2010-3570, CVE-2010-3571, CVE-2010-3572, CVE-2010-3573 and
   CVE-2010-3574.
  
e. vCenter Update Manager Oracle (Sun) JRE update 1.5.0_30

   Oracle (Sun) JRE is updated to version 1.5.0_30, which addresses
   multiple security issues that existed in earlier releases of
   Oracle (Sun) JRE.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the following names to the security issues fixed in
   Oracle (Sun) JRE 1.5.0_30: CVE-2011-0862, CVE-2011-0873,
   CVE-2011-0815, CVE-2011-0864, CVE-2011-0802, CVE-2011-0814,
   CVE-2011-0871, CVE-2011-0867 and CVE-2011-0865.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the following names to the security issues fixed in
   Oracle (Sun) JRE 1.5.0_28: CVE-2010-4447, CVE-2010-4448,
   CVE-2010-4450, CVE-2010-4454, CVE-2010-4462, CVE-2010-4465,
   CVE-2010-4466, CVE-2010-4468, CVE-2010-4469, CVE-2010-4473,
   CVE-2010-4475, CVE-2010-4476.

f. Integer overflow in VMware third-party component sfcb

   This release resolves an integer overflow issue present in the
   third-party library SFCB when the httpMaxContentLength has been
   changed from its default value to 0 in in /etc/sfcb/sfcb.cfg.
   The integer overflow could allow remote attackers to cause a
   denial of service (heap memory corruption) or possibly execute
   arbitrary code via a large integer in the Content-Length HTTP
   header.
  
   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-2054 to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2012/000169.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Applet2ClassLoader Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/28");
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


init_esx_check(date:"2011-10-27");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201111201-SG",
    patch_updates : make_list("ESX400-201203401-SG", "ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201203401-SG",
    patch_updates : make_list("ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG")
  )
) flag++;
if (esx_check(ver:"ESX 4.0", patch:"ESX400-201203406-SG")) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201110201-SG",
    patch_updates : make_list("ESX410-201201401-SG", "ESX410-201204401-SG", "ESX410-201205401-SG", "ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201110204-SG",
    patch_updates : make_list("ESX410-201208103-SG", "ESX410-201208106-SG", "ESX410-201307403-SG", "ESX410-201307404-SG", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201110206-SG",
    patch_updates : make_list("ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201110214-SG",
    patch_updates : make_list("ESX410-201201404-SG", "ESX410-201211405-SG", "ESX410-201307402-SG", "ESX410-201312403-SG", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESX410-201110201-SG",
    patch_updates : make_list("ESX410-201201401-SG", "ESX410-201204401-SG", "ESX410-201205401-SG", "ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
