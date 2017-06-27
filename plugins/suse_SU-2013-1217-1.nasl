#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:1217-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83592);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2013-1968", "CVE-2013-2112");
  script_bugtraq_id(60264, 60267);

  script_name(english:"SUSE SLED10 Security Update : subversion (SUSE-SU-2013:1217-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of subversion fixes two potential DoS vulnerabilities
(bug#821505, CVE-2013-1968, CVE-2013-2112).

Server-side bugfixes :

   - fix FSFS repository corruption due to newline in
    filename (issue #4340)
  - fix svnserve exiting when a client connection is aborted
    (r1482759) Other tool improvements and bugfixes :

   - fix argument processing in contrib hook scripts
    (r1485350)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=36021bc879cc7c6cd3d36b5f76b9c22d
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?501be5d2"
  );
  # http://download.suse.com/patch/finder/?keywords=64648aca6f33898d15cd8c0c4956232f
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e80f83c7"
  );
  # http://download.suse.com/patch/finder/?keywords=f1e3ccee3d6965d85d10d4c4ff3e6746
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f32d4b52"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1968.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2112.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/821505"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20131217-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68bac0d0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Studio Onsite 1.3 :

zypper in -t patch slestso13-subversion-7930

SUSE Linux Enterprise Software Development Kit 11 SP3 :

zypper in -t patch sdksp3-subversion-7933

SUSE Linux Enterprise Software Development Kit 11 SP2 :

zypper in -t patch sdksp2-subversion-7930

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/17");
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
if (! ereg(pattern:"^(SLED10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLED10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"subversion-1.3.1-1.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"subversion-devel-1.3.1-1.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"subversion-1.3.1-1.24.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"subversion-devel-1.3.1-1.24.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "subversion");
}
