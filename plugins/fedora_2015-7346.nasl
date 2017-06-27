#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-7346.
#

include("compat.inc");

if (description)
{
  script_id(83227);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2015/10/19 23:14:52 $");

  script_cve_id("CVE-2015-2170", "CVE-2015-2221", "CVE-2015-2222", "CVE-2015-2668");
  script_xref(name:"FEDORA", value:"2015-7346");

  script_name(english:"Fedora 22 : clamav-0.98.7-1.fc22 (2015-7346)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ClamAV 0.98.7 =============

This release contains new scanning features and bug fixes.

  - Improvements to PDF processing: decryption, escape
    sequence handling, and file property collection.

    - Scanning/analysis of additional Microsoft Office 2003
      XML format.

    - Fix infinite loop condition on crafted y0da cryptor
      file. Identified and patch suggested by Sebastian
      Andrzej Siewior. CVE-2015-2221.

    - Fix crash on crafted petite packed file. Reported and
      patch supplied by Sebastian Andrzej Siewior.
      CVE-2015-2222.

    - Fix false negatives on files within iso9660
      containers. This issue was reported by Minzhuan Gong.

    - Fix a couple crashes on crafted upack packed file.
      Identified and patches supplied by Sebastian Andrzej
      Siewior.

    - Fix a crash during algorithmic detection on crafted PE
      file. Identified and patch supplied by Sebastian
      Andrzej Siewior.

    - Fix an infinite loop condition on a crafted 'xz'
      archive file. This was reported by Dimitri Kirchner
      and Goulven Guiheux. CVE-2015-2668.

    - Fix compilation error after ./configure
      --disable-pthreads. Reported and fix suggested by John
      E. Krokes.

    - Apply upstream patch for possible heap overflow in
      Henry Spencer's regex library. CVE-2015-2305.

    - Fix crash in upx decoder with crafted file. Discovered
      and patch supplied by Sebastian Andrzej Siewior.
      CVE-2015-2170.

    - Fix segfault scanning certain HTML files. Reported
      with sample by Kai Risku.

    - Improve detections within xar/pkg files.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1217206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1217207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1217208"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1217209"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-May/157033.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fdbeabcf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected clamav package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:22");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^22([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 22.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC22", reference:"clamav-0.98.7-1.fc22")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav");
}
