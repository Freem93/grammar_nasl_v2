#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-592.
#

include("compat.inc");

if (description)
{
  script_id(85750);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/09/03 13:42:47 $");

  script_cve_id("CVE-2015-6563", "CVE-2015-6564");
  script_xref(name:"ALAS", value:"2015-592");

  script_name(english:"Amazon Linux AMI : openssh (ALAS-2015-592)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The monitor component in sshd in OpenSSH before 7.0 on non-OpenBSD
platforms accepts extraneous username data in MONITOR_REQ_PAM_INIT_CTX
requests, which allows local users to conduct impersonation attacks by
leveraging any SSH login access in conjunction with control of the
sshd uid to send a crafted MONITOR_REQ_PWNAM request, related to
monitor.c and monitor_wrap.c. (CVE-2015-6563)

Use-after-free vulnerability in the mm_answer_pam_free_ctx function in
monitor.c in sshd in OpenSSH before 7.0 on non-OpenBSD platforms might
allow local users to gain privileges by leveraging control of the sshd
uid to send an unexpectedly early MONITOR_REQ_PAM_FREE_CTX request.
(CVE-2015-6564)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-592.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openssh' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-keycat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/03");
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
if (rpm_check(release:"ALA", reference:"openssh-6.2p2-8.45.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-clients-6.2p2-8.45.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-debuginfo-6.2p2-8.45.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-keycat-6.2p2-8.45.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-ldap-6.2p2-8.45.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-server-6.2p2-8.45.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"pam_ssh_agent_auth-0.9.3-5.8.45.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-clients / openssh-debuginfo / openssh-keycat / etc");
}
