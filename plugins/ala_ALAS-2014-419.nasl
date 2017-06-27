#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-419.
#

include("compat.inc");

if (description)
{
  script_id(78362);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/05 13:48:44 $");

  script_cve_id("CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187");
  script_xref(name:"ALAS", value:"2014-419");
  script_xref(name:"IAVA", value:"2014-A-0142");

  script_name(english:"Amazon Linux AMI : bash (ALAS-2014-419)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"GNU Bash through 4.3 bash43-025 processes trailing strings after
certain malformed function definitions in the values of environment
variables, which allows remote attackers to write to files or possibly
have unknown other impact via a crafted environment, as demonstrated
by vectors involving the ForceCommand feature in OpenSSH sshd, the
mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts
executed by unspecified DHCP clients, and other situations in which
setting the environment occurs across a privilege boundary from Bash
execution.

NOTE: this vulnerability exists because of an incomplete fix for
CVE-2014-6271 and this bulletin is a follow-up to ALAS-2014-418.

It was discovered that the fixed-sized redir_stack could be forced to
overflow in the Bash parser, resulting in memory corruption, and
possibly leading to arbitrary code execution when evaluating untrusted
input that would not otherwise be run as code.

An off-by-one error was discovered in the way Bash was handling deeply
nested flow control constructs. Depending on the layout of the .bss
segment, this could allow arbitrary execution of code that would not
otherwise be executed by Bash.

Special notes :

Because of the exceptional nature of this security event, we have
backfilled our 2014.03, 2013.09, and 2013.03 Amazon Linux AMI
repositories with new bash packages that also fix both CVE-2014-7169
and CVE-2014-6271 .

For 2014.09 Amazon Linux AMIs, 'bash-4.1.2-15.21.amzn1' addresses both
CVEs. Running 'yum clean all' followed by 'yum update bash' will
install the fixed package.

For Amazon Linux AMIs 'locked' to the 2014.03 repositories,
'bash-4.1.2-15.21.amzn1' also addresses both CVEs. Running 'yum clean
all' followed by 'yum update bash' will install the fixed package.

For Amazon Linux AMIs 'locked' to the 2013.09 or 2013.03 repositories,
'bash-4.1.2-15.18.22.amzn1' addresses both CVEs. Running 'yum clean
all' followed by 'yum update bash' will install the fixed package.

For Amazon Linux AMIs 'locked' to the 2012.09, 2012.03, or 2011.09
repositories, run 'yum clean all' followed by 'yum
--releasever=2013.03 update bash' to install only the updated bash
package.

If you are using a pre-2011.09 Amazon Linux AMI, then you are using a
version of the Amazon Linux AMI that was part of our public beta, and
we encourage you to move to a newer version of the Amazon Linux AMI as
soon as possible."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aws.amazon.com/amazon-linux-ami/faqs/#lock"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-418.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-419.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update bash' to update your system. Note that you may need to
run 'yum clean all' first."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bash-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"bash-4.1.2-15.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bash-debuginfo-4.1.2-15.21.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bash-doc-4.1.2-15.21.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash / bash-debuginfo / bash-doc");
}
