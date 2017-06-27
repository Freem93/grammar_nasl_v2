#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57105);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/25 23:46:54 $");

  script_cve_id("CVE-2010-0296", "CVE-2010-0830");

  script_name(english:"SuSE 11.1 Security Update : glibc (SAT Patch Number 2700)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of glibc fixes the following bugs and security issues :

  - The implementation of initgroups() of the nss_compat
    module omits all NIS groups at the second invocation
    within the same process, and also uses a needlessly
    inefficient method to determine the NIS groups.

  - An integer overflow that allows arbitrary code execution
    by running ld.so --verify could be exploited by a
    specially crafted binary. (CVE-2010-0830)

  - The addmntent() function does not escape the newline
    character properly, allowing the user to insert
    arbitrary newlines to /etc/mtab. This could be exploited
    to insert custom entries into /etc/mtab if addmntent()
    gets called by a setuid mount binary that does not
    perform extra input checking. (CVE-2010-0296)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=592941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=594263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=607064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0296.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0830.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 2700.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-locale-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:glibc-profile-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-2.11.1-0.18.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-32bit-2.11.1-0.18.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-devel-2.11.1-0.18.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-devel-32bit-2.11.1-0.18.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-html-2.11.1-0.18.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-i18ndata-2.11.1-0.18.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-info-2.11.1-0.18.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-locale-2.11.1-0.18.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-locale-32bit-2.11.1-0.18.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-profile-2.11.1-0.18.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"glibc-profile-32bit-2.11.1-0.18.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"nscd-2.11.1-0.18.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
