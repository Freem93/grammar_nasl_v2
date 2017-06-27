#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-473.
#

include("compat.inc");

if (description)
{
  script_id(81024);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_osvdb_id(117579);
  script_xref(name:"CERT", value:"967332");
  script_xref(name:"ALAS", value:"2015-473");

  script_name(english:"Amazon Linux AMI : glibc (ALAS-2015-473)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A heap-based buffer overflow was found in glibc's
__nss_hostname_digits_dots() function, which is used by the
gethostbyname() and gethostbyname2() glibc function calls. A remote
attacker able to make an application call to either of these functions
can use this flaw to execute arbitrary code with the permissions of
the user running the application.

Special notes :

Because of the exceptional nature of this security event, we have
backfilled our 2014.03 and 2013.09 Amazon Linux AMI repositories with
new glibc packages that fix CVE-2015-0235 .

For 2014.09 Amazon Linux AMIs, 'glibc-2.17-55.93.amzn1' addresses the
CVE. Running 'yum clean all' followed by 'yum update glibc' will
install the fixed package, and you should reboot your instance after
installing the update.

For Amazon Linux AMIs 'locked' to the 2014.03 repositories, the same
'glibc-2.17-55.93.amzn1' addresses the CVE. Running 'yum clean all'
followed by 'yum update glibc' will install the fixed package, and you
should reboot your instance after installing the update.

For Amazon Linux AMIs 'locked' to the 2013.09 repositories,
'glibc-2.12-1.149.49.amzn1' addresses the CVE. Running 'yum clean all'
followed by 'yum update glibc' will install the fixed package, and you
should reboot your instance after installing the update.

For Amazon Linux AMIs 'locked' to the 2013.03, 2012.09, 2012.03, or
2011.09 repositories, run 'yum clean all' followed by 'yum
--releasever=2013.09 update glibc' to install the updated glibc
package. You should reboot your instance after installing the update.

If you are using a pre-2011.09 Amazon Linux AMI, then you are using a
version of the Amazon Linux AMI that was part of our public beta, and
we encourage you to move to a newer version of the Amazon Linux AMI as
soon as possible."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-473.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update glibc' to update your system. Note that you may need
to run 'yum clean all' first. Once this update has been applied,
'reboot your instance to ensure that all processes and daemons that
link against glibc are using the updated version'. On new instance
launches, you should still reboot after cloud-init has automatically
applied this update."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

# Checks for below glibc-2.17
if (rpm_check(release:"ALA", reference:"glibc-2.17-0.0.amzn1"))
{
  # Clean out initial report from first check
  __rpm_report = '';
  if (rpm_check(release:"ALA", reference:"glibc-2.12-1.149.49.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"glibc-common-2.12-1.149.49.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"glibc-debuginfo-2.12-1.149.49.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"glibc-debuginfo-common-2.12-1.149.49.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"glibc-devel-2.12-1.149.49.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"glibc-headers-2.12-1.149.49.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"glibc-static-2.12-1.149.49.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"glibc-utils-2.12-1.149.49.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"nscd-2.12-1.149.49.amzn1")) flag++;
}
else
{
  # Checks for glibc-2.17
  # Clean out initial report from first check
  __rpm_report = '';
  if (rpm_check(release:"ALA", reference:"glibc-2.17-55.93.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"glibc-common-2.17-55.93.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"glibc-debuginfo-2.17-55.93.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"glibc-debuginfo-common-2.17-55.93.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"glibc-devel-2.17-55.93.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"glibc-headers-2.17-55.93.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"glibc-static-2.17-55.93.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"glibc-utils-2.17-55.93.amzn1")) flag++;
  if (rpm_check(release:"ALA", reference:"nscd-2.17-55.93.amzn1")) flag++;
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-debuginfo / glibc-debuginfo-common / etc");
}
