#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0897 and 
# Oracle Linux Security Advisory ELSA-2008-0897 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67752);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/07 20:57:50 $");

  script_cve_id("CVE-2008-1145", "CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905", "CVE-2008-4310");
  script_bugtraq_id(30644, 30682, 31699);
  script_xref(name:"RHSA", value:"2008:0897");

  script_name(english:"Oracle Linux 4 / 5 : ruby (ELSA-2008-0897)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0897 :

Updated ruby packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Ruby is an interpreted scripting language for quick and easy
object-oriented programming.

The Ruby DNS resolver library, resolv.rb, used predictable transaction
IDs and a fixed source port when sending DNS requests. A remote
attacker could use this flaw to spoof a malicious reply to a DNS
query. (CVE-2008-3905)

Ruby's XML document parsing module (REXML) was prone to a denial of
service attack via XML documents with large XML entity definitions
recursion. A specially crafted XML file could cause a Ruby application
using the REXML module to use an excessive amount of CPU and memory.
(CVE-2008-3790)

An insufficient 'taintness' check flaw was discovered in Ruby's DL
module, which provides direct access to the C language functions. An
attacker could use this flaw to bypass intended safe-level
restrictions by calling external C functions with the arguments from
an untrusted tainted inputs. (CVE-2008-3657)

A denial of service flaw was discovered in WEBrick, Ruby's HTTP server
toolkit. A remote attacker could send a specially crafted HTTP request
to a WEBrick server that would cause the server to use an excessive
amount of CPU time. (CVE-2008-3656)

A number of flaws were found in the safe-level restrictions in Ruby.
It was possible for an attacker to create a carefully crafted
malicious script that can allow the bypass of certain safe-level
restrictions. (CVE-2008-3655)

A denial of service flaw was found in Ruby's regular expression
engine. If a Ruby script tried to process a large amount of data via a
regular expression, it could cause Ruby to enter an infinite-loop and
crash. (CVE-2008-3443)

Users of ruby should upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-October/000767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-October/000769.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 22, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"irb-1.8.1-7.0.1.el4_7.1")) flag++;
if (rpm_check(release:"EL4", reference:"ruby-1.8.1-7.0.1.el4_7.1")) flag++;
if (rpm_check(release:"EL4", reference:"ruby-devel-1.8.1-7.0.1.el4_7.1")) flag++;
if (rpm_check(release:"EL4", reference:"ruby-docs-1.8.1-7.0.1.el4_7.1")) flag++;
if (rpm_check(release:"EL4", reference:"ruby-libs-1.8.1-7.0.1.el4_7.1")) flag++;
if (rpm_check(release:"EL4", reference:"ruby-mode-1.8.1-7.0.1.el4_7.1")) flag++;
if (rpm_check(release:"EL4", reference:"ruby-tcltk-1.8.1-7.0.1.el4_7.1")) flag++;

if (rpm_check(release:"EL5", reference:"ruby-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-devel-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-docs-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-irb-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-libs-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-mode-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-rdoc-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-ri-1.8.5-5.el5_2.5")) flag++;
if (rpm_check(release:"EL5", reference:"ruby-tcltk-1.8.5-5.el5_2.5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irb / ruby / ruby-devel / ruby-docs / ruby-irb / ruby-libs / etc");
}
