#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1424 and 
# Oracle Linux Security Advisory ELSA-2011-1424 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68383);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/28 19:01:50 $");

  script_cve_id("CVE-2011-2939", "CVE-2011-3597");
  script_bugtraq_id(49858, 49911);
  script_osvdb_id(75990);
  script_xref(name:"RHSA", value:"2011:1424");

  script_name(english:"Oracle Linux 6 : perl (ELSA-2011-1424)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1424 :

Updated perl packages that fix two security issues are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Perl is a high-level programming language commonly used for system
administration utilities and web programming.

A heap-based buffer overflow flaw was found in the way Perl decoded
Unicode strings. An attacker could create a malicious Unicode string
that, when decoded by a Perl program, would cause the program to crash
or, potentially, execute arbitrary code with the permissions of the
user running the program. (CVE-2011-2939)

It was found that the 'new' constructor of the Digest module used its
argument as part of the string expression passed to the eval()
function. An attacker could possibly use this flaw to execute
arbitrary Perl code with the privileges of a Perl program that uses
untrusted input as an argument to the constructor. (CVE-2011-3597)

All Perl users should upgrade to these updated packages, which contain
backported patches to correct these issues. All running Perl programs
must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-November/002447.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Archive-Extract");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Archive-Tar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-CGI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-CPANPLUS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Compress-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Digest-SHA");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-CBuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-MakeMaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-ExtUtils-ParseXS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-File-Fetch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IO-Compress-Base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IO-Compress-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-IPC-Cmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Log-Message");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Log-Message-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-CoreList");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Load");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Load-Conditional");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Module-Pluggable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Object-Accessor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Package-Constants");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Params-Check");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Parse-CPAN-Meta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Pod-Escapes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Pod-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Term-UI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Test-Harness");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Test-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Time-HiRes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-parent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-suidperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-version");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/03");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"perl-5.10.1-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Archive-Extract-0.38-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Archive-Tar-1.58-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-CGI-3.51-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-CPAN-1.9402-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-CPANPLUS-0.88-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Compress-Zlib-2.020-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Digest-SHA-5.47-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-ExtUtils-CBuilder-0.27-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-ExtUtils-Embed-1.28-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-ExtUtils-MakeMaker-6.55-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-ExtUtils-ParseXS-2.2003.0-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-File-Fetch-0.26-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-IO-Compress-Base-2.020-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-IO-Compress-Zlib-2.020-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-IO-Zlib-1.09-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-IPC-Cmd-0.56-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Locale-Maketext-Simple-0.18-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Log-Message-0.02-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Log-Message-Simple-0.04-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Module-Build-0.3500-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Module-CoreList-2.18-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Module-Load-0.16-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Module-Load-Conditional-0.30-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Module-Loaded-0.02-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Module-Pluggable-3.90-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Object-Accessor-0.34-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Package-Constants-0.02-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Params-Check-0.26-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Parse-CPAN-Meta-1.40-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Pod-Escapes-1.04-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Pod-Simple-3.13-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Term-UI-0.20-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Test-Harness-3.17-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Test-Simple-0.92-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Time-HiRes-1.9721-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-Time-Piece-1.15-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-core-5.10.1-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-devel-5.10.1-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-libs-5.10.1-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-parent-0.221-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-suidperl-5.10.1-119.el6_1.1")) flag++;
if (rpm_check(release:"EL6", reference:"perl-version-0.77-119.el6_1.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-Archive-Extract / perl-Archive-Tar / perl-CGI / etc");
}
