#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from VMware Security Advisory 2010-0013. 
# The text itself is copyright (C) VMware Inc.
#

include("compat.inc");

if (description)
{
  script_id(49085);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id("CVE-2005-4268", "CVE-2007-4476", "CVE-2008-5302", "CVE-2008-5303", "CVE-2010-0624", "CVE-2010-1168", "CVE-2010-1321", "CVE-2010-1447", "CVE-2010-2063");
  script_bugtraq_id(16057, 38628, 40235, 40302, 40305, 40884);
  script_osvdb_id(22194, 42149, 50446, 62857, 62950, 64744, 64756, 65518, 65683);
  script_xref(name:"VMSA", value:"2010-0013");

  script_name(english:"VMSA-2010-0013 : VMware ESX third-party updates for Service Console");
  script_summary(english:"Checks esxupdate output for the patches");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote VMware ESX host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"a. Service Console update for cpio

   The service console package cpio is updated to version 2.5-6.RHEL3
   for ESX 3.x versions and updated to version 2.6-23.el5_4.1 for
   ESX 4.x versions.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2005-4268 and CVE-2010-0624 to the issues
   addressed in the update for ESX 3.x and the names CVE-2007-4476 and
   CVE-2010-0624 to the issues addressed in the update for ESX 4.x.

b. Service Console update for tar

   The service console package tar is updated to version
   1.13.25-16.RHEL3 for ESX 3.x versions and updated to version
   1.15.1-23.0.1.el5_4.2 for ESX 4.x versions.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-0624 to the issue addressed in the
   update for ESX 3.x and the names CVE-2007-4476 and CVE-2010-0624
   to the issues addressed in the update for ESX 4.x.

c. Service Console update for samba

   The service console packages for samba are updated to version
   samba-3.0.9-1.3E.17vmw, samba-client-3.0.9-1.3E.17vmw and
   samba-common-3.0.9-1.3E.17vmw.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-2063 to the issue addressed in this
   update.

   Note :
   The issue mentioned above is present in the Samba server (smbd) and
   is not present in the Samba client or Samba common packages.

   To determine if your system has Samba server installed do a
   'rpm -q samba`.

   The following lists when the Samba server is installed on the ESX
   service console :

   - ESX 4.0, ESX 4.1
     The Samba server is not present on ESX 4.0 and ESX 4.1.

   - ESX 3.5
     The Samba server is present if an earlier patch for Samba has been
     installed.

   - ESX 3.0.3
     The Samba server is present if ESX 3.0.3 was upgraded from an
     earlier version of ESX 3 and a Samba patch was installed on that
     version.

   The Samba server is not needed to operate the service console and
   can be be disabled without loss of functionality to the service
   console.

d. Service Console update for krb5

   The service console package krb5 is updated to version 1.2.7-72
   for ESX 3.x versions and to version 1.6.1-36.el5_5.4 for ESX 4.x
   versions.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the name CVE-2010-1321 to the issue addressed in
   these updates.

e. Service Console update for perl

   The service console package perl is updated to version
   5.8.0-101.EL3 for ESX 3.x versions and version 5.8.8-32.el5_5.1
   for ESX 4.x versions.

   The Common Vulnerabilities and Exposures project (cve.mitre.org)
   has assigned the names CVE-2010-1168 and CVE-2010-1447 to the issues
   addressed in the update for ESX 3.x and the names CVE-2008-5302,
   CVE-2008-5303, CVE-2010-1168, and CVE-2010-1447 to the issues
   addressed in the update for ESX 4.x."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.vmware.com/pipermail/security-announce/2011/000125.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply the missing patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba chain_reply Memory Corruption (Linux x86)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.0.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:3.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esx:4.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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


init_esx_check(date:"2010-08-31");
flag = 0;


if (esx_check(ver:"ESX 3.0.3", patch:"ESX303-201102402-SG")) flag++;

if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201008405-SG")) flag++;
if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201008407-SG")) flag++;
if (
  esx_check(
    ver           : "ESX 3.5.0",
    patch         : "ESX350-201008410-SG",
    patch_updates : make_list("ESX350-201012408-SG")
  )
) flag++;
if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201008411-SG")) flag++;
if (esx_check(ver:"ESX 3.5.0", patch:"ESX350-201008412-SG")) flag++;

if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201009402-SG",
    patch_updates : make_list("ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201009403-SG",
    patch_updates : make_list("ESX400-201110403-SG", "ESX400-201203407-SG", "ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201009406-SG",
    patch_updates : make_list("ESX400-Update03", "ESX400-Update04")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.0",
    patch         : "ESX400-201009411-SG",
    patch_updates : make_list("ESX400-Update03", "ESX400-Update04")
  )
) flag++;

if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201010409-SG",
    patch_updates : make_list("ESX40-TO-ESX41UPDATE01", "ESX410-Update01", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201010412-SG",
    patch_updates : make_list("ESX40-TO-ESX41UPDATE01", "ESX410-Update01", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;
if (
  esx_check(
    ver           : "ESX 4.1",
    patch         : "ESX410-201010413-SG",
    patch_updates : make_list("ESX40-TO-ESX41UPDATE01", "ESX410-Update01", "ESX410-Update02", "ESX410-Update03")
  )
) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:esx_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
