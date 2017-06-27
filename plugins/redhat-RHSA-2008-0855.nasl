#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0855. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34034);
  script_version ("$Revision: 1.32 $");
  script_cvs_date("$Date: 2017/01/04 15:20:05 $");

  script_cve_id("CVE-2007-4752", "CVE-2008-3844");
  script_bugtraq_id(25628, 30794);
  script_osvdb_id(47635);
  script_xref(name:"RHSA", value:"2008:0855");
  script_xref(name:"IAVT", value:"2008-T-0046");

  script_name(english:"RHEL 4 / 5 : openssh (RHSA-2008:0855)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssh packages are now available for Red Hat Enterprise
Linux 4, Red Hat Enterprise Linux 5, and Red Hat Enterprise Linux 4.5
Extended Update Support.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

OpenSSH is OpenBSD's SSH (Secure SHell) protocol implementation.

Last week Red Hat detected an intrusion on certain of its computer
systems and took immediate action. While the investigation into the
intrusion is on-going, our initial focus was to review and test the
distribution channel we use with our customers, Red Hat Network (RHN)
and its associated security measures. Based on these efforts, we
remain highly confident that our systems and processes prevented the
intrusion from compromising RHN or the content distributed via RHN and
accordingly believe that customers who keep their systems updated
using Red Hat Network are not at risk. We are issuing this alert
primarily for those who may obtain Red Hat binary packages via
channels other than those of official Red Hat subscribers.

In connection with the incident, the intruder was able to sign a small
number of OpenSSH packages relating only to Red Hat Enterprise Linux 4
(i386 and x86_64 architectures only) and Red Hat Enterprise Linux 5
(x86_64 architecture only). As a precautionary measure, we are
releasing an updated version of these packages, and have published a
list of the tampered packages and how to detect them at
http://www.redhat.com/security/data/openssh-blacklist.html

To reiterate, our processes and efforts to date indicate that packages
obtained by Red Hat Enterprise Linux subscribers via Red Hat Network
are not at risk.

These packages also fix a low severity flaw in the way ssh handles X11
cookies when creating X11 forwarding connections. When ssh was unable
to create untrusted cookie, ssh used a trusted cookie instead,
possibly allowing the administrative user of a untrusted remote
server, or untrusted application run on the remote server, to gain
unintended access to a users local X server. (CVE-2007-4752)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4752.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-3844.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.redhat.com/security/data/openssh-blacklist.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0855.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/24");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2008:0855";
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
if (sp == "5") {   if (rpm_check(release:"RHEL4", sp:"5", reference:"openssh-3.9p1-10.RHEL4.20")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"openssh-3.9p1-11.el4_7")) flag++; }

if (sp == "5") {   if (rpm_check(release:"RHEL4", sp:"5", reference:"openssh-askpass-3.9p1-10.RHEL4.20")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"openssh-askpass-3.9p1-11.el4_7")) flag++; }

if (sp == "5") {   if (rpm_check(release:"RHEL4", sp:"5", reference:"openssh-askpass-gnome-3.9p1-10.RHEL4.20")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"openssh-askpass-gnome-3.9p1-11.el4_7")) flag++; }

if (sp == "5") {   if (rpm_check(release:"RHEL4", sp:"5", reference:"openssh-clients-3.9p1-10.RHEL4.20")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"openssh-clients-3.9p1-11.el4_7")) flag++; }

if (sp == "5") {   if (rpm_check(release:"RHEL4", sp:"5", reference:"openssh-server-3.9p1-10.RHEL4.20")) flag++; }
  else { if (rpm_check(release:"RHEL4", reference:"openssh-server-3.9p1-11.el4_7")) flag++; }


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssh-4.3p2-26.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssh-4.3p2-26.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssh-4.3p2-26.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssh-askpass-4.3p2-26.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssh-askpass-4.3p2-26.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssh-askpass-4.3p2-26.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssh-clients-4.3p2-26.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssh-clients-4.3p2-26.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssh-clients-4.3p2-26.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openssh-server-4.3p2-26.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openssh-server-4.3p2-26.el5_2.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openssh-server-4.3p2-26.el5_2.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-askpass / openssh-askpass-gnome / openssh-clients / etc");
  }
}
