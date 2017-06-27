#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:1920-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83604);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_name(english:"SUSE SLED11 / SLES11 Security Update : libfreebl3 (SUSE-SU-2013:1920-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla NSS has been updated to the 3.15.3.1 security release.

The update blacklists an intermediate CA that was abused to create man
in the middle certificates.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=a417469719590c5d5345b9512a640f6b
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb79c505"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/854367"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20131920-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd87be23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11 SP2 :

zypper in -t patch sdksp2-nss-201312-8648

SUSE Linux Enterprise Server 11 SP2 for VMware :

zypper in -t patch slessp2-nss-201312-8648

SUSE Linux Enterprise Server 11 SP2 :

zypper in -t patch slessp2-nss-201312-8648

SUSE Linux Enterprise Desktop 11 SP2 :

zypper in -t patch sledsp2-nss-201312-8648

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/19");
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
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^2$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^2$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"libfreebl3-32bit-3.15.3.1-0.4.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.15.3.1-0.4.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"libfreebl3-32bit-3.15.3.1-0.4.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"mozilla-nss-32bit-3.15.3.1-0.4.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libfreebl3-3.15.3.1-0.4.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nss-3.15.3.1-0.4.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"mozilla-nss-tools-3.15.3.1-0.4.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"libfreebl3-3.15.3.1-0.4.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"mozilla-nss-3.15.3.1-0.4.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"mozilla-nss-tools-3.15.3.1-0.4.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"libfreebl3-32bit-3.15.3.1-0.4.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"mozilla-nss-32bit-3.15.3.1-0.4.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"libfreebl3-3.15.3.1-0.4.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"mozilla-nss-3.15.3.1-0.4.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"mozilla-nss-tools-3.15.3.1-0.4.2.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libfreebl3");
}
