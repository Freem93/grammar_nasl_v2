#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0488. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47034);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/01/04 15:51:47 $");

  script_cve_id("CVE-2010-2063");
  script_osvdb_id(65518);
  script_xref(name:"RHSA", value:"2010:0488");

  script_name(english:"RHEL 3 / 4 / 5 : samba and samba3x (RHSA-2010:0488)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba and samba3x packages that fix one security issue are now
available for Red Hat Enterprise Linux 3, 4, and 5, and Red Hat
Enterprise Linux 4.7, 5.3, and 5.4 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Samba is a suite of programs used by machines to share files,
printers, and other information.

An input sanitization flaw was found in the way Samba parsed client
data. A malicious client could send a specially crafted SMB packet to
the Samba server, resulting in arbitrary code execution with the
privileges of the Samba server (smbd). (CVE-2010-2063)

Red Hat would like to thank the Samba team for responsibly reporting
this issue. Upstream acknowledges Jun Mao as the original reporter.

Users of Samba are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing
this update, the smb service will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0488.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba chain_reply Memory Corruption (Linux x86)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtalloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba3x-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tdb-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0488";
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
  if (rpm_check(release:"RHEL3", reference:"samba-3.0.9-1.3E.17")) flag++;

  if (rpm_check(release:"RHEL3", reference:"samba-client-3.0.9-1.3E.17")) flag++;

  if (rpm_check(release:"RHEL3", reference:"samba-common-3.0.9-1.3E.17")) flag++;

  if (rpm_check(release:"RHEL3", reference:"samba-swat-3.0.9-1.3E.17")) flag++;


if (sp == "7") {   if (rpm_check(release:"RHEL4", sp:"7", reference:"samba-3.0.28-0.10.el4_7")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"samba-3.0.33-0.19.el4_8.1")) flag++; }

if (sp == "7") {   if (rpm_check(release:"RHEL4", sp:"7", reference:"samba-client-3.0.28-0.10.el4_7")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"samba-client-3.0.33-0.19.el4_8.1")) flag++; }

if (sp == "7") {   if (rpm_check(release:"RHEL4", sp:"7", reference:"samba-common-3.0.28-0.10.el4_7")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"samba-common-3.0.33-0.19.el4_8.1")) flag++; }

if (sp == "7") {   if (rpm_check(release:"RHEL4", sp:"7", reference:"samba-swat-3.0.28-0.10.el4_7")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"samba-swat-3.0.33-0.19.el4_8.1")) flag++; }


  if (rpm_check(release:"RHEL5", reference:"libsmbclient-3.0.33-3.29.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libsmbclient-devel-3.0.33-3.29.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libtalloc-1.2.0-52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libtalloc-devel-1.2.0-52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libtdb-1.1.2-52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libtdb-devel-1.1.2-52.el5_5")) flag++;

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"i386", reference:"samba-3.0.33-3.15.el5_4.2")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"samba-3.0.33-3.7.el5_3.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba-3.0.33-3.29.el5_5")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"samba-3.0.33-3.15.el5_4.2")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"samba-3.0.33-3.7.el5_3.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba-3.0.33-3.29.el5_5")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"samba-3.0.33-3.15.el5_4.2")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"samba-3.0.33-3.7.el5_3.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba-3.0.33-3.29.el5_5")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"i386", reference:"samba-client-3.0.33-3.15.el5_4.2")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"samba-client-3.0.33-3.7.el5_3.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba-client-3.0.33-3.29.el5_5")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"samba-client-3.0.33-3.15.el5_4.2")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"samba-client-3.0.33-3.7.el5_3.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba-client-3.0.33-3.29.el5_5")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"samba-client-3.0.33-3.15.el5_4.2")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"samba-client-3.0.33-3.7.el5_3.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba-client-3.0.33-3.29.el5_5")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", reference:"samba-common-3.0.33-3.15.el5_4.2")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", reference:"samba-common-3.0.33-3.7.el5_3.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", reference:"samba-common-3.0.33-3.29.el5_5")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"i386", reference:"samba-swat-3.0.33-3.15.el5_4.2")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"samba-swat-3.0.33-3.7.el5_3.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba-swat-3.0.33-3.29.el5_5")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"s390x", reference:"samba-swat-3.0.33-3.15.el5_4.2")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"s390x", reference:"samba-swat-3.0.33-3.7.el5_3.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba-swat-3.0.33-3.29.el5_5")) flag++; }

if (sp == "4") {   if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"samba-swat-3.0.33-3.15.el5_4.2")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"samba-swat-3.0.33-3.7.el5_3.2")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba-swat-3.0.33-3.29.el5_5")) flag++; }

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-client-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-client-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-client-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-common-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-common-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-common-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-doc-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-doc-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-doc-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-domainjoin-gui-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-domainjoin-gui-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-domainjoin-gui-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba3x-swat-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba3x-swat-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba3x-swat-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"samba3x-winbind-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", reference:"samba3x-winbind-devel-3.3.8-0.52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tdb-tools-1.1.2-52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tdb-tools-1.1.2-52.el5_5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tdb-tools-1.1.2-52.el5_5")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / libtalloc / libtalloc-devel / etc");
  }
}
