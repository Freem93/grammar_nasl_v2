#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0466. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58673);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2012-1182");
  script_osvdb_id(81303);
  script_xref(name:"RHSA", value:"2012:0466");

  script_name(english:"RHEL 5 : samba3x (RHSA-2012:0466)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba3x packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and Red Hat Enterprise Linux 5.6
Extended Update Support.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Samba is an open source implementation of the Server Message Block
(SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other
information.

A flaw in the Samba suite's Perl-based DCE/RPC IDL (PIDL) compiler,
used to generate code to handle RPC calls, resulted in multiple buffer
overflows in Samba. A remote, unauthenticated attacker could send a
specially crafted RPC request that would cause the Samba daemon (smbd)
to crash or, possibly, execute arbitrary code with the privileges of
the root user. (CVE-2012-1182)

Users of Samba are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing
this update, the smb service will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0466.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba SetInformationPolicy AuditEventsInfo Heap Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0466";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{  sp = get_kb_item("Host/RedHat/minor_release");
  if (isnull(sp)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");

  flag = 0;
if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"samba3x-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"samba3x-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"samba3x-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"samba3x-client-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-client-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"samba3x-client-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-client-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"samba3x-client-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-client-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"samba3x-common-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-common-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"samba3x-common-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-common-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"samba3x-common-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-common-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"samba3x-doc-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-doc-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"samba3x-doc-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-doc-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"samba3x-doc-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-doc-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"samba3x-domainjoin-gui-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-domainjoin-gui-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"samba3x-domainjoin-gui-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-domainjoin-gui-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"samba3x-domainjoin-gui-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-domainjoin-gui-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"samba3x-swat-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-swat-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"samba3x-swat-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-swat-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"samba3x-swat-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-swat-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", reference:"samba3x-winbind-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", reference:"samba3x-winbind-3.5.10-0.108.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", reference:"samba3x-winbind-devel-3.5.4-0.70.el5_6.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", reference:"samba3x-winbind-devel-3.5.10-0.108.el5_8")) flag++; }


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba3x / samba3x-client / samba3x-common / samba3x-doc / etc");
  }
}
