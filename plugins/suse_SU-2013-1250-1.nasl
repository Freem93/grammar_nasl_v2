#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:1250-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83593);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_name(english:"SUSE SLED11 Security Update : lcms2 (SUSE-SU-2013:1250-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"lcms2 has been updated to the version 2.5 which is a maintenance
release to fix various security and other bugs.

  - User defined parametric curves can now be saved in ICC
    profiles.

  - RGB profiles using same tone curves for several channels
    are storing now only one copy of the curve

  - update black point detection algorithm to reflect ICC
    changes

  - Added new cmsPlugInTHR() and fixed some race conditions

  - Added error descriptions on cmsSmoothToneCurve

  - Several improvements in cgats parser.

  - Fixed devicelink generation for 8 bits

  - Added a reference for Mac MLU tag

  - Added a way to read the profile creator from header

  - Added identity curves support for write V2 LUT

  - Added TIFF Lab16 handling on tifficc

  - Fixed a bug in parametric curves

  - Rendering intent used when creating the transform is now
    propagated to profile header in cmsTransform2Devicelink.

  - Transform2Devicelink now keeps white point when guessing
    deviceclass is enabled

  - Added some checks for non-happy path, mostly failing
    mallocs (bnc#826097).

For further changes please see the ChangeLog in the RPM.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=3746092820e850d9766ee08526b7fa10
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?480a2fc0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/826097"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20131250-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30776393"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11 SP3 :

zypper in -t patch sdksp3-lcms2-8091

SUSE Linux Enterprise Desktop 11 SP3 :

zypper in -t patch sledsp3-lcms2-8091

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lcms2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:liblcms2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/24");
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
if (! ereg(pattern:"^(SLED11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "i386|i486|i586|i686|x86_64") audit(AUDIT_ARCH_NOT, "i386 / i486 / i586 / i686 / x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED11" && (! ereg(pattern:"^3$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"lcms2-2.5-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"liblcms2-2-2.5-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"lcms2-2.5-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"liblcms2-2-2.5-0.7.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "lcms2");
}
