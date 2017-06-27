#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2828-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(94939);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2016/12/27 20:33:26 $");

  script_cve_id("CVE-2016-5407", "CVE-2016-7942", "CVE-2016-7944", "CVE-2016-7945", "CVE-2016-7946", "CVE-2016-7947", "CVE-2016-7948", "CVE-2016-7949", "CVE-2016-7950", "CVE-2016-7951", "CVE-2016-7952", "CVE-2016-7953");
  script_osvdb_id(145119, 145120, 145121, 145123, 145124, 145125, 145126, 145127, 145128, 145129, 145237, 145238);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : X Window System client libraries (SUSE-SU-2016:2828-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for the X Window System client libraries fixes a class of
privilege escalation issues. A malicious X Server could send specially
crafted data to X clients, which allowed for triggering crashes, or
privilege escalation if this relationship was untrusted or crossed
user or permission level boundaries. libX11, libXfixes, libXi,
libXrandr, libXrender, libXtst, libXv, libXvMC were fixed,
specifically: libX11 :

  - CVE-2016-7942: insufficient validation of data from the
    X server allowed out of boundary memory read
    (bsc#1002991) libXfixes :

  - CVE-2016-7944: insufficient validation of data from the
    X server can cause an integer overflow on 32 bit
    architectures (bsc#1002995) libXi :

  - CVE-2016-7945, CVE-2016-7946: insufficient validation of
    data from the X server can cause out of boundary memory
    access or endless loops (Denial of Service)
    (bsc#1002998) libXtst :

  - CVE-2016-7951, CVE-2016-7952: insufficient validation of
    data from the X server can cause out of boundary memory
    access or endless loops (Denial of Service)
    (bsc#1003012) libXv :

  - CVE-2016-5407: insufficient validation of data from the
    X server can cause out of boundary memory and memory
    corruption (bsc#1003017) libXvMC :

  - CVE-2016-7953: insufficient validation of data from the
    X server can cause a one byte buffer read underrun
    (bsc#1003023) libXrender :

  - CVE-2016-7949, CVE-2016-7950: insufficient validation of
    data from the X server can cause out of boundary memory
    writes (bsc#1003002) libXrandr :

  - CVE-2016-7947, CVE-2016-7948: insufficient validation of
    data from the X server can cause out of boundary memory
    writes (bsc#1003000)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1002991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1002995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1002998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5407.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7942.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7944.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7945.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7946.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7947.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7948.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7949.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7950.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7951.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7952.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7953.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162828-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?79ce64ec"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2016-1668=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2016-1668=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2016-1668=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2016-1668=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libX11-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libX11-6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libX11-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libX11-xcb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libX11-xcb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXfixes-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXfixes3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXfixes3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXi6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXi6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXrender-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXrender1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXrender1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXtst-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXtst6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXtst6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXv1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXv1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXvMC-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXvMC1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libXvMC1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/17");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libX11-6-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libX11-6-debuginfo-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libX11-debugsource-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libX11-xcb1-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libX11-xcb1-debuginfo-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXfixes-debugsource-5.0.1-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXfixes3-5.0.1-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXfixes3-debuginfo-5.0.1-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXi-debugsource-1.7.4-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXi6-1.7.4-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXi6-debuginfo-1.7.4-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXrender-debugsource-0.9.8-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXrender1-0.9.8-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXrender1-debuginfo-0.9.8-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXtst-debugsource-1.2.2-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXtst6-1.2.2-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXtst6-debuginfo-1.2.2-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXv-debugsource-1.0.10-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXv1-1.0.10-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXv1-debuginfo-1.0.10-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXvMC-debugsource-1.0.8-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXvMC1-1.0.8-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXvMC1-debuginfo-1.0.8-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libX11-6-32bit-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libX11-6-debuginfo-32bit-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libX11-xcb1-32bit-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libX11-xcb1-debuginfo-32bit-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXfixes3-32bit-5.0.1-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXfixes3-debuginfo-32bit-5.0.1-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXi6-32bit-1.7.4-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXi6-debuginfo-32bit-1.7.4-14.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXrender1-32bit-0.9.8-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXrender1-debuginfo-32bit-0.9.8-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXtst6-32bit-1.2.2-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXtst6-debuginfo-32bit-1.2.2-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXv1-32bit-1.0.10-7.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libXv1-debuginfo-32bit-1.0.10-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libX11-6-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libX11-6-32bit-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libX11-6-debuginfo-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libX11-6-debuginfo-32bit-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libX11-debugsource-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libX11-xcb1-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libX11-xcb1-32bit-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libX11-xcb1-debuginfo-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libX11-xcb1-debuginfo-32bit-1.6.2-8.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXfixes-debugsource-5.0.1-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXfixes3-32bit-5.0.1-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXfixes3-5.0.1-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXfixes3-debuginfo-32bit-5.0.1-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXfixes3-debuginfo-5.0.1-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXi-debugsource-1.7.4-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXi6-1.7.4-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXi6-32bit-1.7.4-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXi6-debuginfo-1.7.4-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXi6-debuginfo-32bit-1.7.4-14.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXrender-debugsource-0.9.8-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXrender1-0.9.8-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXrender1-32bit-0.9.8-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXrender1-debuginfo-0.9.8-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXrender1-debuginfo-32bit-0.9.8-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXtst-debugsource-1.2.2-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXtst6-1.2.2-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXtst6-32bit-1.2.2-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXtst6-debuginfo-1.2.2-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXtst6-debuginfo-32bit-1.2.2-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXv-debugsource-1.0.10-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXv1-1.0.10-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXv1-32bit-1.0.10-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXv1-debuginfo-1.0.10-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXv1-debuginfo-32bit-1.0.10-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXvMC-debugsource-1.0.8-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXvMC1-1.0.8-7.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libXvMC1-debuginfo-1.0.8-7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "X Window System client libraries");
}
