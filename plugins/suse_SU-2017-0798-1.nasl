#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0798-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(97913);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/23 13:29:51 $");

  script_cve_id("CVE-2016-10163", "CVE-2016-10214", "CVE-2017-5580", "CVE-2017-5937", "CVE-2017-5956", "CVE-2017-5957", "CVE-2017-5993", "CVE-2017-5994", "CVE-2017-6209", "CVE-2017-6210", "CVE-2017-6317", "CVE-2017-6355", "CVE-2017-6386");
  script_osvdb_id(150798, 150911, 151849, 151852, 151924, 151925, 152151, 152152, 152468, 152476, 152522, 152618, 152706);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : virglrenderer (SUSE-SU-2017:0798-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for virglrenderer fixes the following issues: Security
issues fixed :

  - CVE-2017-6386: memory leakage while in
    vrend_create_vertex_elements_state (bsc#1027376)

  - CVE-2017-6355: integer overflow while creating shader
    object (bsc#1027108)

  - CVE-2017-6317: fix memory leak in add shader program
    (bsc#1026922)

  - CVE-2017-6210: NULL pointer dereference in
    vrend_decode_reset (bsc#1026725)

  - CVE-2017-6209: stack buffer oveflow in parse_identifier
    (bsc#1026723)

  - CVE-2017-5994: out-of-bounds access in
    vrend_create_vertex_elements_state (bsc#1025507)

  - CVE-2017-5993: host memory leakage when initialising
    blitter context (bsc#1025505)

  - CVE-2017-5957: stack overflow in
    vrend_decode_set_framebuffer_state (bsc#1024993)

  - CVE-2017-5956: OOB access while in vrend_draw_vbo
    (bsc#1024992)

  - CVE-2017-5937: NULL pointer dereference in vrend_clear
    (bsc#1024232)

  - CVE-2017-5580: OOB access while parsing texture
    instruction (bsc#1021627)

  - CVE-2016-10214: host memory leak issue in
    virgl_resource_attach_backing (bsc#1024244)

  - CVE-2016-10163: host memory leakage when creating decode
    context (bsc#1021616)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021627"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1025505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1025507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026922"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10163.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10214.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5580.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5937.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5956.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5957.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5993.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5994.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6209.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6210.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6317.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6355.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6386.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170798-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f989e1b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-452=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-452=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-452=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-452=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirglrenderer0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libvirglrenderer0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:virglrenderer-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libvirglrenderer0-0.5.0-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"libvirglrenderer0-debuginfo-0.5.0-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"virglrenderer-debugsource-0.5.0-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirglrenderer0-0.5.0-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"libvirglrenderer0-debuginfo-0.5.0-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"virglrenderer-debugsource-0.5.0-11.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "virglrenderer");
}
