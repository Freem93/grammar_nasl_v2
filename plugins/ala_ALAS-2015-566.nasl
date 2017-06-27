#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2015-566.
#

include("compat.inc");

if (description)
{
  script_id(84926);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2015/09/13 04:38:19 $");

  script_cve_id("CVE-2015-4620");
  script_xref(name:"ALAS", value:"2015-566");

  script_name(english:"Amazon Linux AMI : bind (ALAS-2015-566)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way BIND performed DNSSEC validation. An
attacker able to make BIND (functioning as a DNS resolver with DNSSEC
validation enabled) resolve a name in an attacker-controlled domain
could cause named to exit unexpectedly with an assertion failure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2015-566.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update bind' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-chroot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-sdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/23");
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
if (rpm_check(release:"ALA", reference:"bind-9.8.2-0.30.rc1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-chroot-9.8.2-0.30.rc1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-debuginfo-9.8.2-0.30.rc1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-devel-9.8.2-0.30.rc1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-libs-9.8.2-0.30.rc1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-sdb-9.8.2-0.30.rc1.37.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"bind-utils-9.8.2-0.30.rc1.37.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind / bind-chroot / bind-debuginfo / bind-devel / bind-libs / etc");
}
