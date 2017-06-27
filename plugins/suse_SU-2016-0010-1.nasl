#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0010-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87857);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2015-7512", "CVE-2015-8345");
  script_osvdb_id(130703, 130889);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : kvm (SUSE-SU-2016:0010-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for kvm fixes the following issues :

Security issues fixed :

  - CVE-2015-7512: The receive packet size is now checked in
    the emulated pcnet driver, eliminating buffer overflow
    and potential security issue by malicious guest systems.
    (bsc#957162)

  - CVE-2015-8345: A infinite loop in processing command
    block list was fixed that could be exploit by malicious
    guest systems (bsc#956829).

Other bugs fixed :

  - To assist users past the migration incompatibility
    discussed in bsc#950590 (restore migration compatibility
    with SLE11 SP3 and SLE12, at the unfortunate expense to
    prior SLE11 SP4 kvm release compatability when a
    virtio-net device is used), print a message which
    references the support document TID 7017048. See
    https://www.suse.com/support/kb/doc.php?id=7017048

  - Fix cases of wrong clock values in kvmclock timekeeping
    (bsc#947164 and bsc#953187)

  - Enforce pxe rom sizes to ensure migration compatibility.
    (bsc#950590)

  - Fix kvm live migration fails between sles11 sp3 and sp4
    (bsc#950590)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/953187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7512.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8345.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/support/kb/doc.php?id=7017048"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160010-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aff89398"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-kvm-12293=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-kvm-12293=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/12");
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
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"kvm-1.4.2-35.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"kvm-1.4.2-35.1")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"kvm-1.4.2-35.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kvm");
}
