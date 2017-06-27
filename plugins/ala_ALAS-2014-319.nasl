#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-319.
#

include("compat.inc");

if (description)
{
  script_id(73569);
  script_version("$Revision $");
  script_cvs_date("$Date: 2014/04/16 16:30:41 $");

  script_xref(name:"ALAS", value:"2014-319");

  script_name(english:"Amazon Linux AMI Update: kernel / openssh Denial of Service (ALAS-2014-319)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(attribute:"synopsis", value:"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Due to a problem with the configuration of kernels 3.10.34-37 and
3.10.34-38 and their interaction with the authentication modules
stack, the sshd daemon that is part of the openssh package will no
longer allow remote logins following a restart of the sshd service.");

  # http://aws.amazon.com/amazon-linux-ami/security-bulletins/ALAS-2014-319/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70e74915");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update openssh kernel' to update the system. A reboot will be
necessary for the new kernel on the instance.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-keycat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/16");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
# If we are below kernel-3.10.34-37, there is no issue
if (rpm_check(release:"ALA", reference:"kernel-3.10.34-37")) audit(AUDIT_PACKAGE_NOT_AFFECTED, "kernel");

# If we are at kernel-3.10.34-39 or higher, there is no issue
if (rpm_check(release:"ALA", reference:"kernel-3.10.34-39"))
{
  # We're affected. Flag and add any affected openssh packages to the report. Versions same for i686, x86_64
  flag++;
  rpm_check(release:"ALA", reference:"openssh-6.2p2-7.40.amzn1");
  rpm_check(release:"ALA", reference:"openssh-clients-6.2p2-7.40.amzn1");
  rpm_check(release:"ALA", reference:"openssh-debuginfo-6.2p2-7.40.amzn1");
  rpm_check(release:"ALA", reference:"openssh-ldap-6.2p2-7.40.amzn1");
  rpm_check(release:"ALA", reference:"openssh-keycat-6.2p2-7.40.amzn1");
  rpm_check(release:"ALA", reference:"openssh-server-6.2p2-7.40.amzn1");
  rpm_check(release:"ALA", reference:"pam_ssh_agent_auth-0.9.3-5.7.40.amzn1");
}

if (flag)
{
  report_data = rpm_report_get() + 'This kernel may not be the currently running kernel version.\nOpenSSH should be updated in case that kernel gets used.\n';
  if (report_verbosity > 0) security_warning(port:0, extra:report_data);
  else security_warning(0);
  exit(0);
}
else
{
  # If we rely on pkg_tests_get() here we're going to get "kernel-3.10.34-37 / kernel-3.10.34-39".
  # The openssh checks never execute before we get here.
  audit(AUDIT_PACKAGE_NOT_AFFECTED, "kernel");
  # We know kernel is installed. Skip AUDIT_PACKAGE_NOT_INSTALLED.
}
