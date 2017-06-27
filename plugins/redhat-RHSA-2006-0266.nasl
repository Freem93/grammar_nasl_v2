#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0266. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21090);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/29 15:35:19 $");

  script_cve_id("CVE-2006-0049", "CVE-2006-0455");
  script_osvdb_id(23221, 23790);
  script_xref(name:"RHSA", value:"2006:0266");

  script_name(english:"RHEL 2.1 / 3 / 4 : gnupg (RHSA-2006:0266)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated GnuPG package that fixes signature verification flaws as
well as minor bugs is now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

GnuPG is a utility for encrypting data and creating digital
signatures.

Tavis Ormandy discovered a bug in the way GnuPG verifies
cryptographically signed data with detached signatures. It is possible
for an attacker to construct a cryptographically signed message which
could appear to come from a third party. When a victim processes a
GnuPG message with a malformed detached signature, GnuPG ignores the
malformed signature, processes and outputs the signed data, and exits
with status 0, just as it would if the signature had been valid. In
this case, GnuPG's exit status would not indicate that no signature
verification had taken place. This issue would primarily be of concern
when processing GnuPG results via an automated script. The Common
Vulnerabilities and Exposures project assigned the name CVE-2006-0455
to this issue.

Tavis Ormandy also discovered a bug in the way GnuPG verifies
cryptographically signed data with inline signatures. It is possible
for an attacker to inject unsigned data into a signed message in such
a way that when a victim processes the message to recover the data,
the unsigned data is output along with the signed data, gaining the
appearance of having been signed. This issue is mitigated in the GnuPG
shipped with Red Hat Enterprise Linux as the --ignore-crc-error option
must be passed to the gpg executable for this attack to be successful.
The Common Vulnerabilities and Exposures project assigned the name
CVE-2006-0049 to this issue.

Please note that neither of these issues affect the way RPM or up2date
verify RPM package files, nor is RPM vulnerable to either of these
issues.

All users of GnuPG are advised to upgrade to this updated package,
which contains backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-0049.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2006-0455.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2006-0266.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gnupg package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnupg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/03/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2006:0266";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"gnupg-1.0.7-16")) flag++;

  if (rpm_check(release:"RHEL3", reference:"gnupg-1.2.1-15")) flag++;

  if (rpm_check(release:"RHEL4", reference:"gnupg-1.2.6-3")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnupg");
  }
}
