#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0550-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83704);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2013-7423", "CVE-2014-0475", "CVE-2014-7817", "CVE-2014-9402", "CVE-2015-1472");
  script_bugtraq_id(68505, 71216, 71670, 72428, 72498, 72844);
  script_osvdb_id(108943, 115032, 116139, 117751, 117873);

  script_name(english:"SUSE SLES10 Security Update : glibc (SUSE-SU-2015:0550-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"glibc has been updated to fix four security issues :

  - CVE-2014-0475: Directory traversal in locale environment
    handling (bnc#887022)

  - CVE-2014-7817: wordexp failed to honour WRDE_NOCMD
    (bsc#906371)

  - CVE-2014-9402: Avoid infinite loop in nss_dns
    getnetbyname (bsc#910599)

  - CVE-2015-1472: Fixed buffer overflow in wscanf
    (bsc#916222)

This non-security issue has been fixed :

  - Fix missing zero termination (bnc#918233)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=ddad3e23b15c5919bf5e29a0fcedc637
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b33569f9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7423.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-7817.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9402.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-1472.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/887022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/906371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/916222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918233"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150550-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90bd2014"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected glibc packages");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"glibc-32bit-2.4-31.117.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"glibc-devel-32bit-2.4-31.117.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"glibc-locale-32bit-2.4-31.117.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"glibc-profile-32bit-2.4-31.117.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"glibc-32bit-2.4-31.117.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"glibc-devel-32bit-2.4-31.117.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"glibc-locale-32bit-2.4-31.117.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"glibc-profile-32bit-2.4-31.117.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-2.4-31.117.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-devel-2.4-31.117.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-html-2.4-31.117.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-i18ndata-2.4-31.117.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-info-2.4-31.117.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-locale-2.4-31.117.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-profile-2.4-31.117.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"nscd-2.4-31.117.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
