#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1601-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93152);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2015-3622", "CVE-2016-4008");
  script_bugtraq_id(74419);
  script_osvdb_id(121517, 136947);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : libtasn1 (SUSE-SU-2016:1601-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libtasn1 fixes the following issues :

  - Malformed asn1 definitions could have caused a
    segmentation fault in the asn1 definition parser
    (bsc#961491)

  - CVE-2015-3622: Fixed invalid read in octet string
    decoding (bsc#929414)

  - CVE-2016-4008: Fixed infinite loop while parsing DER
    certificates (bsc#982779)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3622.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4008.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161601-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e7b8479"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-949=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-949=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-949=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-949=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-949=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-949=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtasn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtasn1-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtasn1-6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtasn1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtasn1-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
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

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtasn1-3.7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtasn1-6-3.7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtasn1-6-debuginfo-3.7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtasn1-debuginfo-3.7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtasn1-debugsource-3.7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtasn1-6-32bit-3.7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"libtasn1-6-debuginfo-32bit-3.7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtasn1-3.7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtasn1-6-3.7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtasn1-6-debuginfo-3.7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtasn1-debuginfo-3.7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtasn1-debugsource-3.7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtasn1-6-32bit-3.7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtasn1-6-debuginfo-32bit-3.7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtasn1-3.7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtasn1-6-3.7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtasn1-6-32bit-3.7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtasn1-6-debuginfo-3.7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtasn1-6-debuginfo-32bit-3.7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtasn1-debuginfo-3.7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libtasn1-debugsource-3.7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtasn1-3.7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtasn1-6-3.7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtasn1-6-32bit-3.7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtasn1-6-debuginfo-3.7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtasn1-6-debuginfo-32bit-3.7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtasn1-debuginfo-3.7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libtasn1-debugsource-3.7-11.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtasn1");
}
