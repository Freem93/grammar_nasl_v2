#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2015:083. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(82336);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/01/10 05:42:14 $");

  script_cve_id("CVE-2014-8143", "CVE-2015-0240");
  script_xref(name:"MDVSA", value:"2015:083");

  script_name(english:"Mandriva Linux Security Advisory : samba4 (MDVSA-2015:083)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been discovered and corrected in samba4 :

Samba 4.0.x before 4.0.24, 4.1.x before 4.1.16, and 4.2.x before
4.2rc4, when an Active Directory Domain Controller (AD DC) is
configured, allows remote authenticated users to set the LDB
userAccountControl UF_SERVER_TRUST_ACCOUNT bit, and consequently gain
privileges, by leveraging delegation of authority for user-account or
computer-account creation (CVE-2014-8143).

An uninitialized pointer use flaw was found in the Samba daemon
(smbd). A malicious Samba client could send specially crafted netlogon
packets that, when processed by smbd, could potentially lead to
arbitrary code execution with the privileges of the user running smbd
(by default, the root user) (CVE-2015-0240).

The updated packages provides a solution for these security issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/history/samba-4.1.15.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/history/samba-4.1.16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/history/samba-4.1.17.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2014-8143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2015-0240"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64samba4-dc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64samba4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64samba4-smbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64samba4-smbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64samba4-test-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64samba4-test0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64samba4-wbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64samba4-wbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64samba41");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-samba4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-pidl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-vfs-glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-winbind-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-winbind-krb5-locator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba4-winbind-modules");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64samba4-dc0-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64samba4-devel-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64samba4-smbclient-devel-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64samba4-smbclient0-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64samba4-test-devel-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64samba4-test0-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64samba4-wbclient-devel-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64samba4-wbclient0-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"lib64samba41-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"python-samba4-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"samba4-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"samba4-client-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"samba4-common-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"samba4-dc-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", reference:"samba4-pidl-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"samba4-test-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"samba4-vfs-glusterfs-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"samba4-winbind-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"samba4-winbind-clients-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"samba4-winbind-krb5-locator-4.1.17-1.mbs2")) flag++;
if (rpm_check(release:"MDK-MBS2", cpu:"x86_64", reference:"samba4-winbind-modules-4.1.17-1.mbs2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
