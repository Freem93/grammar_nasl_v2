#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2011-0003. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(51971);
  script_version("$Revision: 1.41 $");
  script_cvs_date("$Date: 2016/11/30 14:45:01 $");

  script_cve_id("CVE-2008-0085", "CVE-2008-0086", "CVE-2008-0106", "CVE-2008-0107", "CVE-2008-3825", "CVE-2008-5416", "CVE-2009-1384", "CVE-2009-2693", "CVE-2009-2901", "CVE-2009-2902", "CVE-2009-3548", "CVE-2009-3555", "CVE-2009-4308", "CVE-2010-0003", "CVE-2010-0007", "CVE-2010-0008", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085", "CVE-2010-0087", "CVE-2010-0088", "CVE-2010-0089", "CVE-2010-0090", "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093", "CVE-2010-0094", "CVE-2010-0095", "CVE-2010-0291", "CVE-2010-0307", "CVE-2010-0410", "CVE-2010-0415", "CVE-2010-0433", "CVE-2010-0437", "CVE-2010-0622", "CVE-2010-0730", "CVE-2010-0734", "CVE-2010-0740", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0839", "CVE-2010-0840", "CVE-2010-0841", "CVE-2010-0842", "CVE-2010-0843", "CVE-2010-0844", "CVE-2010-0845", "CVE-2010-0846", "CVE-2010-0847", "CVE-2010-0848", "CVE-2010-0849", "CVE-2010-0850", "CVE-2010-0886", "CVE-2010-1084", "CVE-2010-1085", "CVE-2010-1086", "CVE-2010-1087", "CVE-2010-1088", "CVE-2010-1157", "CVE-2010-1173", "CVE-2010-1187", "CVE-2010-1321", "CVE-2010-1436", "CVE-2010-1437", "CVE-2010-1641", "CVE-2010-2066", "CVE-2010-2070", "CVE-2010-2226", "CVE-2010-2227", "CVE-2010-2240", "CVE-2010-2248", "CVE-2010-2521", "CVE-2010-2524", "CVE-2010-2928", "CVE-2010-2939", "CVE-2010-3081", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3550", "CVE-2010-3551", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3556", "CVE-2010-3557", "CVE-2010-3559", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3571", "CVE-2010-3572", "CVE-2010-3573", "CVE-2010-3574", "CVE-2010-3864");
  script_bugtraq_id(30082, 30083, 30118, 30119, 31534, 32710, 35112, 36935, 36954, 37724, 37762, 37906, 37942, 37944, 37945, 38027, 38058, 38144, 38162, 38165, 38185, 38348, 38479, 38533, 38857, 38898, 39013, 39044, 39062, 39067, 39068, 39069, 39070, 39071, 39072, 39073, 39075, 39077, 39078, 39081, 39082, 39083, 39084, 39085, 39086, 39088, 39089, 39090, 39091, 39093, 39094, 39095, 39096, 39120, 39492, 39569, 39635, 39715, 39719, 39794, 39979, 40235, 40356, 40776, 40920, 41466, 41544, 41904, 42242, 42249, 42306, 43239, 43965, 43971, 43979, 43985, 43988, 43992, 43994, 44009, 44011, 44012, 44013, 44014, 44016, 44017, 44026, 44027, 44028, 44030, 44032, 44035, 44040, 44884);
  script_osvdb_id(46770, 46771, 46772, 46773, 48784, 50589, 54791, 60176, 61035, 61670, 61784, 61984, 62045, 62052, 62053, 62054, 62079, 62168, 62217, 62379, 62380, 62507, 62719, 63146, 63257, 63299, 63452, 63481, 63482, 63483, 63484, 63485, 63486, 63487, 63488, 63489, 63490, 63491, 63492, 63493, 63494, 63495, 63496, 63497, 63498, 63499, 63500, 63501, 63502, 63503, 63504, 63505, 63506, 63630, 63631, 63632, 63633, 63634, 63635, 63636, 63798, 64023, 64549, 64557, 64630, 64744, 64865, 65066, 65541, 65631, 66319, 66582, 66946, 67237, 67243, 67244, 67892, 68213, 69033, 69034, 69035, 69036, 69038, 69039, 69040, 69041, 69042, 69044, 69045, 69047, 69049, 69050, 69052, 69053, 69055, 69056, 69057, 69058, 69059, 69265, 70083, 70859);
  script_xref(name:"VMSA", value:"2011-0003");
  script_xref(name:"IAVA", value:"2011-A-0066");

  script_name(english:"VMSA-2011-0003 : Third-party component updates for VMware vCenter Server, vCenter Update Manager, ESXi and ESX");
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
"a. vCenter Server and vCenter Update Manager update Microsoft
   SQL Server 2005 Express Edition to Service Pack 3

   Microsoft SQL Server 2005 Express Edition (SQL Express)
   distributed with vCenter Server 4.1 Update 1 and vCenter Update
   Manager 4.1 Update 1 is upgraded from  SQL Express Service Pack 2
   to SQL Express Service Pack 3, to address multiple security
   issues that exist in the earlier releases of Microsoft SQL Express.

   Customers using other database solutions need not update for
   these issues.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2008-5416, CVE-2008-0085, CVE-2008-0086,
   CVE-2008-0107 and CVE-2008-0106 to the issues addressed in MS SQL
   Express Service Pack 3.

b. vCenter Apache Tomcat Management Application Credential Disclosure

   The Apache Tomcat Manager application configuration file contains
   logon credentials that can be read by unprivileged local users.

   The issue is resolved by removing the Manager application in
   vCenter 4.1 Update 1.

   If vCenter 4.1 is updated to vCenter 4.1 Update 1 the logon
   credentials are not present in the configuration file after the
   update.

   VMware would like to thank Claudio Criscione of Secure Networking
   for reporting this issue to us.

   The Common Vulnerabilities and Exposures Project (cve.mitre.org)
   has assigned the name CVE-2010-2928 to this issue.

c. vCenter Server and ESX, Oracle (Sun) JRE is updated to version
   1.6.0_21

   Oracle (Sun) JRE update to version 1.6.0_21, which addresses
   multiple security issues that existed in earlier releases of
   Oracle (Sun) JRE.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the following names to the security issues fixed in
   Oracle (Sun) JRE 1.6.0_19: CVE-2009-3555, CVE-2010-0082,
   CVE-2010-0084, CVE-2010-0085, CVE-2010-0087, CVE-2010-0088,
   CVE-2010-0089, CVE-2010-0090, CVE-2010-0091, CVE-2010-0092,
   CVE-2010-0093, CVE-2010-0094, CVE-2010-0095, CVE-2010-0837,
   CVE-2010-0838, CVE-2010-0839, CVE-2010-0840, CVE-2010-0841,
   CVE-2010-0842, CVE-2010-0843, CVE-2010-0844, CVE-2010-0845,
   CVE-2010-0846, CVE-2010-0847, CVE-2010-0848, CVE-2010-0849,
   CVE-2010-0850.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the following name to the security issue fixed in
   Oracle (Sun) JRE 1.6.0_20: CVE-2010-0886.

d. vCenter Update Manager Oracle (Sun) JRE is updated to version
  1.5.0_26

   Oracle (Sun) JRE update to version 1.5.0_26, which addresses
   multiple security issues that existed in earlier releases of
   Oracle (Sun) JRE.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the following names to the security issues fixed in
   Oracle (Sun) JRE 1.5.0_26: CVE-2010-3556, CVE-2010-3566,
   CVE-2010-3567, CVE-2010-3550, CVE-2010-3561, CVE-2010-3573,
   CVE-2010-3565,CVE-2010-3568, CVE-2010-3569,  CVE-2009-3555,
   CVE-2010-1321, CVE-2010-3548, CVE-2010-3551, CVE-2010-3562,
   CVE-2010-3571, CVE-2010-3554, CVE-2010-3559, CVE-2010-3572,
   CVE-2010-3553, CVE-2010-3549, CVE-2010-3557, CVE-2010-3541,
   CVE-2010-3574.

e. vCenter Server and ESX Apache Tomcat updated to version 6.0.28

   Apache Tomcat updated to version 6.0.28, which addresses multiple
   security issues that existed in earlier releases of Apache Tomcat

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the following names to the security issues fixed in
   Apache Tomcat 6.0.24: CVE-2009-2693, CVE-2009-2901, CVE-2009-2902,i
   and CVE-2009-3548.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the following names to the security issues fixed in
   Apache Tomcat 6.0.28: CVE-2010-2227, CVE-2010-1157.

f. vCenter Server third-party component OpenSSL updated to version
   0.9.8n

   The version of the OpenSSL library in vCenter Server is updated to
   0.9.8n.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2010-0740 and CVE-2010-0433 to the
   issues addressed in this version of OpenSSL.

g. ESX third-party component OpenSSL updated to version 0.9.8p

   The version of the ESX OpenSSL library is updated to 0.9.8p.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2010-3864 and CVE-2010-2939 to the
   issues addressed in this update.

h. ESXi third-party component cURL updated

   The version of cURL library in ESXi is updated.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-0734 to the issues addressed in
   this update.

i. ESX third-party component pam_krb5 updated

   The version of pam_krb5 library is updated.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2008-3825 and CVE-2009-1384 to the
   issues addressed in the update.

j. ESX third-party update for Service Console kernel

   The Service Console kernel is updated to include kernel version
   2.6.18-194.11.1.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2010-1084, CVE-2010-2066, CVE-2010-2070,
   CVE-2010-2226, CVE-2010-2248, CVE-2010-2521, CVE-2010-2524,
   CVE-2010-0008, CVE-2010-0415, CVE-2010-0437, CVE-2009-4308,
   CVE-2010-0003, CVE-2010-0007, CVE-2010-0307, CVE-2010-1086,
   CVE-2010-0410, CVE-2010-0730, CVE-2010-1085, CVE-2010-0291,
   CVE-2010-0622, CVE-2010-1087, CVE-2010-1173, CVE-2010-1437,
   CVE-2010-1088, CVE-2010-1187, CVE-2010-1436, CVE-2010-1641, and
   CVE-2010-3081 to the issues addressed in the update.

   Notes :
   - The update also addresses the 64-bit compatibility mode
   stack pointer underflow issue identified by CVE-2010-3081. This
   issue was patched in an ESX 4.1 patch prior to the release of
   ESX 4.1 Update 1 and in a previous ESX 4.0 patch release.
   - The update also addresses CVE-2010-2240 for ESX 4.0."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2011/000140.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Plugin Command Line Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 22, 119, 189, 200, 255, 264, 287, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/14");
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


init_esx_check(date:"2011-02-10");
flag = 0;


if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201103401-SG",
    patch_updates : make_list("ESX400-201104401-SG", "ESX400-201110401-SG", "ESX400-201111201-SG", "ESX400-201203401-SG", "ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201103403-SG",
    patch_updates : make_list("ESX400-201111201-SG", "ESX400-201203401-SG", "ESX400-201205401-SG", "ESX400-201206401-SG", "ESX400-201209401-SG", "ESX400-201302401-SG", "ESX400-201305401-SG", "ESX400-201310401-SG", "ESX400-201404401-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201101201-SG",
    patch_updates : make_list("ESX40-TO-ESX41UPDATE01", "ESX410-201104401-SG", "ESX410-201110201-SG", "ESX410-201201401-SG", "ESX410-201204401-SG", "ESX410-201205401-SG", "ESX410-201206401-SG", "ESX410-201208101-SG", "ESX410-201211401-SG", "ESX410-201301401-SG", "ESX410-201304401-SG", "ESX410-201307401-SG", "ESX410-201312401-SG", "ESX410-201404401-SG", "ESX410-Update01", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.0",
    patch         : "ESXi400-201103401-SG",
    patch_updates : make_list("ESXi400-201104401-SG", "ESXi400-201110401-SG", "ESXi400-201203401-SG", "ESXi400-201205401-SG", "ESXi400-201206401-SG", "ESXi400-201209401-SG", "ESXi400-201302401-SG", "ESXi400-201305401-SG", "ESXi400-201310401-SG", "ESXi400-201404401-SG", "ESXi400-Update03", "ESXi400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESXi 4.1",
    patch         : "ESXi410-201101201-SG",
    patch_updates : make_list("ESXi410-201104401-SG", "ESXi410-201110201-SG", "ESXi410-201201401-SG", "ESXi410-201204401-SG", "ESXi410-201205401-SG", "ESXi410-201206401-SG", "ESXi410-201208101-SG", "ESXi410-201211401-SG", "ESXi410-201301401-SG", "ESXi410-201304401-SG", "ESXi410-201307401-SG", "ESXi410-201312401-SG", "ESXi410-201404401-SG", "ESXi410-Update01", "ESXi410-Update02", "ESXi410-Update03")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
