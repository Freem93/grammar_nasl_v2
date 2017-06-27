#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0332. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58111);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2012-0870");
  script_bugtraq_id(52103);
  script_osvdb_id(79443);
  script_xref(name:"RHSA", value:"2012:0332");

  script_name(english:"RHEL 4 / 5 : samba (RHSA-2012:0332)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba packages that fix one security issue are now available
for Red Hat Enterprise Linux 4 and 5, and Red Hat Enterprise Linux 5.3
Long Life, and 5.6 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Samba is a suite of programs used by machines to share files,
printers, and other information.

An input validation flaw was found in the way Samba handled Any
Batched (AndX) requests. A remote, unauthenticated attacker could send
a specially crafted SMB packet to the Samba server, possibly resulting
in arbitrary code execution with the privileges of the Samba server
(root). (CVE-2012-0870)

Red Hat would like to thank the Samba team for reporting this issue.
Upstream acknowledges Andy Davis of NGS Secure as the original
reporter.

Users of Samba are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing
this update, the smb service will be restarted automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0870.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0332.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/24");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0332";
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
  if (rpm_check(release:"RHEL4", reference:"samba-3.0.33-0.35.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"samba-client-3.0.33-0.35.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"samba-common-3.0.33-0.35.el4")) flag++;

  if (rpm_check(release:"RHEL4", reference:"samba-swat-3.0.33-0.35.el4")) flag++;


if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", reference:"libsmbclient-3.0.33-3.29.el5_6.4")) flag++; }
  else { if (rpm_check(release:"RHEL5", reference:"libsmbclient-3.0.33-3.38.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", reference:"libsmbclient-devel-3.0.33-3.29.el5_6.4")) flag++; }
  else { if (rpm_check(release:"RHEL5", reference:"libsmbclient-devel-3.0.33-3.38.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"samba-3.0.33-3.29.el5_6.4")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"samba-3.0.33-3.7.el5_3.4")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba-3.0.33-3.38.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"samba-3.0.33-3.29.el5_6.4")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba-3.0.33-3.38.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"samba-3.0.33-3.29.el5_6.4")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"samba-3.0.33-3.7.el5_3.4")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba-3.0.33-3.38.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"samba-client-3.0.33-3.29.el5_6.4")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"samba-client-3.0.33-3.7.el5_3.4")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba-client-3.0.33-3.38.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"samba-client-3.0.33-3.29.el5_6.4")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba-client-3.0.33-3.38.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"samba-client-3.0.33-3.29.el5_6.4")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"samba-client-3.0.33-3.7.el5_3.4")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba-client-3.0.33-3.38.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", reference:"samba-common-3.0.33-3.29.el5_6.4")) flag++; }
  else { if (rpm_check(release:"RHEL5", reference:"samba-common-3.0.33-3.38.el5_8")) flag++; }

  if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"samba-common-3.0.33-3.7.el5_3.4")) flag++;

  if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"samba-common-3.0.33-3.7.el5_3.4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"samba-debuginfo-3.0.33-3.38.el5_8")) flag++;

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"samba-swat-3.0.33-3.29.el5_6.4")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"samba-swat-3.0.33-3.7.el5_3.4")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"i386", reference:"samba-swat-3.0.33-3.38.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"samba-swat-3.0.33-3.29.el5_6.4")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"samba-swat-3.0.33-3.38.el5_8")) flag++; }

if (sp == "6") {   if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"samba-swat-3.0.33-3.29.el5_6.4")) flag++; }
else if (sp == "3") {   if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"samba-swat-3.0.33-3.7.el5_3.4")) flag++; }
  else { if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"samba-swat-3.0.33-3.38.el5_8")) flag++; }


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libsmbclient / libsmbclient-devel / samba / samba-client / etc");
  }
}
