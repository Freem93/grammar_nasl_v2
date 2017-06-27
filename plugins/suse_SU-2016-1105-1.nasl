#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1105-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(90623);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/27 20:24:08 $");

  script_cve_id("CVE-2015-5252", "CVE-2016-2110", "CVE-2016-2111");
  script_osvdb_id(131936, 136990, 136991);

  script_name(english:"SUSE SLES10 Security Update : samba (SUSE-SU-2016:1105-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Samba was updated to fix three security issues.

These security issues were fixed :

CVE-2016-2110: A man-in-the-middle could have downgraded NTLMSSP
authentication (bso#11688, bsc#973031).

CVE-2016-2111: Domain controller netlogon member computer could have
been spoofed (bso#11749, bsc#973032).

CVE-2015-5252: Insufficient symlink verification (allowed file access
outside the share) (bso#11395, bnc#958582).

This non-security issue was fixed :

Allow 'delete readonly = yes' to correctly override deletion of a file
(bsc#913087, bso#5073)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/913087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973032"
  );
  # https://download.suse.com/patch/finder/?keywords=7a8b86525db490aaf0868ada97807c68
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3aa3621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5252.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2110.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2111.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161105-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f91fcd4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected samba packages");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cifs-mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ldapsmb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmsrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmsrpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-krb-printing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-vscan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"libsmbclient-32bit-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"samba-32bit-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"samba-client-32bit-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"samba-winbind-32bit-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"libsmbclient-32bit-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"samba-32bit-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"samba-client-32bit-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"samba-winbind-32bit-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"cifs-mount-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"ldapsmb-1.34b-25.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"libmsrpc-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"libmsrpc-devel-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"libsmbclient-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"libsmbclient-devel-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"samba-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"samba-client-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"samba-krb-printing-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"samba-python-3.0.36-0.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"samba-vscan-0.3.6b-43.13.32.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"samba-winbind-3.0.36-0.13.32.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
