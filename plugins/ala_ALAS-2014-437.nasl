#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-437.
#

include("compat.inc");

if (description)
{
  script_id(78780);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/30 14:48:48 $");

  script_cve_id("CVE-2014-7189");
  script_xref(name:"ALAS", value:"2014-437");

  script_name(english:"Amazon Linux AMI : golang (ALAS-2014-437)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"crpyto/tls in Go 1.1 before 1.3.2, when SessionTicketsDisabled is
enabled, allows man-in-the-middle attackers to spoof clients via
unspecified vectors."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-437.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update golang' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:emacs-golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-bin-linux-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-bin-linux-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-darwin-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-darwin-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-freebsd-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-freebsd-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-freebsd-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-linux-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-linux-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-linux-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-netbsd-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-netbsd-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-netbsd-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-openbsd-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-openbsd-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-plan9-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-plan9-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-windows-386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-pkg-windows-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:golang-vim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/03");
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
if (rpm_check(release:"ALA", reference:"emacs-golang-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"golang-pkg-bin-linux-386-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"golang-pkg-bin-linux-amd64-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-darwin-386-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-darwin-amd64-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-freebsd-386-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-freebsd-amd64-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-freebsd-arm-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-linux-386-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-linux-amd64-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-linux-arm-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-netbsd-386-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-netbsd-amd64-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-netbsd-arm-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-openbsd-386-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-openbsd-amd64-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-plan9-386-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-plan9-amd64-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-windows-386-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-pkg-windows-amd64-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-src-1.3.3-1.7.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"golang-vim-1.3.3-1.7.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacs-golang / golang / golang-pkg-bin-linux-386 / etc");
}
