#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:1119-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83634);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2012-4412", "CVE-2013-4237", "CVE-2014-5119");
  script_bugtraq_id(55462, 61729, 68983, 69738);
  script_osvdb_id(96318, 98142, 109188);

  script_name(english:"SUSE SLES10 Security Update : glibc (SUSE-SU-2014:1119-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This glibc update fixes a critical privilege escalation problem and
the following security and non security issues :

  - bnc#892073: An off-by-one error leading to a heap-based
    buffer overflow was found in __gconv_translit_find(). An
    exploit that targets the problem is publicly available.
    (CVE-2014-5119)

  - bnc#772242: Replace scope handing with master state

  - bnc#779320: Fix buffer overflow in strcoll
    (CVE-2012-4412)

  - bnc#818630: Fall back to localhost if no nameserver
    defined

  - bnc#828235: Fix missing character in IBM-943 charset

  - bnc#828637: Fix use of alloca in gaih_inet

  - bnc#834594: Fix readdir_r with long file names
    (CVE-2013-4237)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=767429925ce018c15cbe14c33d6a0f11
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18daf367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4412.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4237.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-5119.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/772242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/779320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/818630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/828235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/828637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/834594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/892073"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20141119-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9acd37d5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected glibc packages");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/11");
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
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"glibc-32bit-2.4-31.111.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"glibc-devel-32bit-2.4-31.111.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"glibc-locale-32bit-2.4-31.111.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"glibc-profile-32bit-2.4-31.111.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"glibc-32bit-2.4-31.111.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"glibc-devel-32bit-2.4-31.111.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"glibc-locale-32bit-2.4-31.111.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"glibc-profile-32bit-2.4-31.111.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-2.4-31.111.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-devel-2.4-31.111.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-html-2.4-31.111.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-i18ndata-2.4-31.111.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-info-2.4-31.111.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-locale-2.4-31.111.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"glibc-profile-2.4-31.111.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"nscd-2.4-31.111.1")) flag++;


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
