#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-625.
#

include("compat.inc");

if (description)
{
  script_id(87351);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/12/15 14:50:16 $");

  script_cve_id("CVE-2015-5600", "CVE-2015-6563", "CVE-2015-6564");
  script_xref(name:"ALAS", value:"2015-625");

  script_name(english:"Amazon Linux AMI : openssh (ALAS-2015-625)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way OpenSSH handled PAM authentication when
using privilege separation. An attacker with valid credentials on the
system and able to fully compromise a non-privileged
pre-authentication process using a different flaw could use this flaw
to authenticate as other users.

It was discovered that the OpenSSH sshd daemon did not check the list
of keyboard-interactive authentication methods for duplicates. A
remote attacker could use this flaw to bypass the MaxAuthTries limit,
making it easier to perform password guessing attacks.

A use-after-free flaw was found in OpenSSH. An attacker able to fully
compromise a non-privileged pre-authentication process using a
different flaw could possibly cause sshd to crash or execute arbitrary
code with root privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-625.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openssh' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-keycat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"openssh-6.6.1p1-22.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-clients-6.6.1p1-22.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-debuginfo-6.6.1p1-22.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-keycat-6.6.1p1-22.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-ldap-6.6.1p1-22.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-server-6.6.1p1-22.58.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"pam_ssh_agent_auth-0.9.3-9.22.58.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-clients / openssh-debuginfo / openssh-keycat / etc");
}
