#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1422. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56698);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/04 16:12:16 $");

  script_cve_id("CVE-2011-4073");
  script_bugtraq_id(50440);
  script_osvdb_id(76725);
  script_xref(name:"RHSA", value:"2011:1422");

  script_name(english:"RHEL 5 / 6 : openswan (RHSA-2011:1422)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openswan packages that fix one security issue are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Openswan is a free implementation of Internet Protocol Security
(IPsec) and Internet Key Exchange (IKE). IPsec uses strong
cryptography to provide both authentication and encryption services.
These services allow you to build secure tunnels through untrusted
networks.

A use-after-free flaw was found in the way Openswan's pluto IKE daemon
used cryptographic helpers. A remote, authenticated attacker could
send a specially crafted IKE packet that would crash the pluto daemon.
This issue only affected SMP (symmetric multiprocessing) systems that
have the cryptographic helpers enabled. The helpers are disabled by
default on Red Hat Enterprise Linux 5, but enabled by default on Red
Hat Enterprise Linux 6. (CVE-2011-4073)

Red Hat would like to thank the Openswan project for reporting this
issue. Upstream acknowledges Petar Tsankov, Mohammad Torabi Dashti and
David Basin of the information security group at ETH Zurich as the
original reporters.

All users of openswan are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue.
After installing this update, the ipsec service will be restarted
automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4073.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1422.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected openswan, openswan-debuginfo and / or openswan-doc
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openswan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openswan-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:1422";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openswan-2.6.21-5.el5_7.6")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openswan-2.6.21-5.el5_7.6")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openswan-2.6.21-5.el5_7.6")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"openswan-doc-2.6.21-5.el5_7.6")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"openswan-doc-2.6.21-5.el5_7.6")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"openswan-doc-2.6.21-5.el5_7.6")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openswan-2.6.32-4.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openswan-2.6.32-4.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openswan-2.6.32-4.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openswan-debuginfo-2.6.32-4.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openswan-debuginfo-2.6.32-4.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openswan-debuginfo-2.6.32-4.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openswan-doc-2.6.32-4.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openswan-doc-2.6.32-4.el6_1.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openswan-doc-2.6.32-4.el6_1.4")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openswan / openswan-debuginfo / openswan-doc");
  }
}
