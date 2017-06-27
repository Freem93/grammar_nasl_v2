#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-543.
#

include("compat.inc");

if (description)
{
  script_id(84244);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/06/18 13:42:58 $");

  script_cve_id("CVE-2014-3215");
  script_xref(name:"ALAS", value:"2015-543");

  script_name(english:"Amazon Linux AMI : libcap-ng (ALAS-2015-543)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way seunshare, a utility for running
executables under a different security context, used the capng_lock
functionality of the libcap-ng library. The subsequent invocation of
suid root binaries that relied on the fact that the setuid() system
call, among others, also sets the saved set-user-ID when dropping the
binaries' process privileges, could allow a local, unprivileged user
to potentially escalate their privileges on the system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-543.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update libcap-ng' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcap-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcap-ng-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcap-ng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcap-ng-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcap-ng-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/18");
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
if (rpm_check(release:"ALA", reference:"libcap-ng-0.7.3-5.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcap-ng-debuginfo-0.7.3-5.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcap-ng-devel-0.7.3-5.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcap-ng-python-0.7.3-5.13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libcap-ng-utils-0.7.3-5.13.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcap-ng / libcap-ng-debuginfo / libcap-ng-devel / etc");
}
