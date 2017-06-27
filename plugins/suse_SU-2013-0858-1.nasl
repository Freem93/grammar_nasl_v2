#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:0858-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83588);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2013-1914");
  script_bugtraq_id(58839);

  script_name(english:"SUSE SLED10 / SLES10 Security Update : glibc (SUSE-SU-2013:0858-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This collective update for the GNU C library (glibc) provides the
following fixes :

  - Fix stack overflow in getaddrinfo with many results
    (bnc#813121, CVE-2013-1914)

  - Fix locking in _IO_cleanup (bnc#796982)

  - Fix buffer overflow in glob (bnc#691365)

  - Fix memory leak in execve (bnc#805899)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=4ca050db7cee063070fd004b2b257e13
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2dfbe98d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1914.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/691365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/796982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/805899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/810637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/813121"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20130858-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7edf911"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected glibc packages");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLED10|SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED10 / SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLED10 SP4", os_ver + " SP" + sp);
if (os_ver == "SLES10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"glibc-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"glibc-devel-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"glibc-html-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"glibc-i18ndata-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"glibc-info-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"glibc-locale-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"nscd-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"glibc-32bit-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"glibc-devel-32bit-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"glibc-locale-32bit-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"glibc-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"glibc-devel-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"glibc-html-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"glibc-i18ndata-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"glibc-info-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"glibc-locale-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"nscd-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"glibc-32bit-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"glibc-devel-32bit-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"glibc-locale-32bit-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"glibc-profile-32bit-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"glibc-32bit-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"glibc-devel-32bit-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"glibc-locale-32bit-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"glibc-profile-32bit-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-devel-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-html-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-i18ndata-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-info-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-locale-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-profile-2.4-31.109.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"nscd-2.4-31.109.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
