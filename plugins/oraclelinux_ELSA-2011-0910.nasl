#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0910 and 
# Oracle Linux Security Advisory ELSA-2011-0910 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68299);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:57:59 $");

  script_cve_id("CVE-2011-0188", "CVE-2011-1004", "CVE-2011-1005");
  script_bugtraq_id(46458, 46460, 46966);
  script_osvdb_id(70957, 70958);
  script_xref(name:"RHSA", value:"2011:0910");

  script_name(english:"Oracle Linux 6 : ruby (ELSA-2011-0910)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0910 :

Updated ruby packages that fix three security issues are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to do system
management tasks.

A flaw was found in the way large amounts of memory were allocated on
64-bit systems when using the BigDecimal class. A context-dependent
attacker could use this flaw to cause memory corruption, causing a
Ruby application that uses the BigDecimal class to crash or, possibly,
execute arbitrary code. This issue did not affect 32-bit systems.
(CVE-2011-0188)

A race condition flaw was found in the remove system entries method in
the FileUtils module. If a local user ran a Ruby script that uses this
method, a local attacker could use this flaw to delete arbitrary files
and directories accessible to that user via a symbolic link attack.
(CVE-2011-1004)

A flaw was found in the method for translating an exception message
into a string in the Exception class. A remote attacker could use this
flaw to bypass safe level 4 restrictions, allowing untrusted (tainted)
code to modify arbitrary, trusted (untainted) strings, which safe
level 4 restrictions would otherwise prevent. (CVE-2011-1005)

Red Hat would like to thank Drew Yao of Apple Product Security for
reporting the CVE-2011-0188 issue.

All Ruby users should upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-June/002209.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"ruby-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"ruby-devel-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"ruby-docs-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"ruby-irb-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"ruby-libs-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"ruby-rdoc-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"ruby-ri-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"ruby-static-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"ruby-tcltk-1.8.7.299-7.el6_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-devel / ruby-docs / ruby-irb / ruby-libs / ruby-rdoc / etc");
}
