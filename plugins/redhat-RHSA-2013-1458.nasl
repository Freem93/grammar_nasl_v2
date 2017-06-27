#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1458. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70601);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2012-6085", "CVE-2013-4242", "CVE-2013-4351", "CVE-2013-4402");
  script_bugtraq_id(57102, 61464, 62857, 62921);
  script_osvdb_id(88865, 88866, 95657, 97339, 98164);
  script_xref(name:"RHSA", value:"2013:1458");

  script_name(english:"RHEL 5 : gnupg (RHSA-2013:1458)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gnupg package that fixes multiple security issues is now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The GNU Privacy Guard (GnuPG or GPG) is a tool for encrypting data and
creating digital signatures, compliant with the proposed OpenPGP
Internet standard and the S/MIME standard.

It was found that GnuPG was vulnerable to the Yarom/Falkner
flush+reload cache side-channel attack on the RSA secret exponent. An
attacker able to execute a process on the logical CPU that shared the
L3 cache with the GnuPG process (such as a different local user or a
user of a KVM guest running on the same host with the kernel same-page
merging functionality enabled) could possibly use this flaw to obtain
portions of the RSA secret key. (CVE-2013-4242)

A denial of service flaw was found in the way GnuPG parsed certain
compressed OpenPGP packets. An attacker could use this flaw to send
specially crafted input data to GnuPG, making GnuPG enter an infinite
loop when parsing data. (CVE-2013-4402)

It was found that importing a corrupted public key into a GnuPG
keyring database corrupted that keyring. An attacker could use this
flaw to trick a local user into importing a specially crafted public
key into their keyring database, causing the keyring to be corrupted
and preventing its further use. (CVE-2012-6085)

It was found that GnuPG did not properly interpret the key flags in a
PGP key packet. GPG could accept a key for uses not indicated by its
holder. (CVE-2013-4351)

Red Hat would like to thank Werner Koch for reporting the
CVE-2013-4402 issue. Upstream acknowledges Taylor R Campbell as the
original reporter.

All gnupg users are advised to upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-6085.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4242.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4351.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4402.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1458.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnupg and / or gnupg-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnupg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:1458";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gnupg-1.4.5-18.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gnupg-1.4.5-18.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gnupg-1.4.5-18.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gnupg-debuginfo-1.4.5-18.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gnupg-debuginfo-1.4.5-18.el5_10")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gnupg-debuginfo-1.4.5-18.el5_10")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnupg / gnupg-debuginfo");
  }
}
