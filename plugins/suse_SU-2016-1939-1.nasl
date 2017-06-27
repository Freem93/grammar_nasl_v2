#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1939-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93187);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2015-2304", "CVE-2015-8918", "CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8924", "CVE-2015-8929", "CVE-2016-4809");
  script_bugtraq_id(73137);
  script_osvdb_id(117148, 118251, 118253, 118255, 118259, 140116, 140484);

  script_name(english:"SUSE SLES11 Security Update : bsdtar (SUSE-SU-2016:1939-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"bsdtar was updated to fix seven security issues. These security issues
were fixed :

  - CVE-2015-8929: Memory leak in tar parser (bsc#985669).

  - CVE-2016-4809: Memory allocate error with symbolic links
    in cpio archives (bsc#984990).

  - CVE-2015-8920: Stack out of bounds read in ar parser
    (bsc#985675).

  - CVE-2015-8921: Global out of bounds read in mtree parser
    (bsc#985682).

  - CVE-2015-8924: Heap buffer read overflow in tar
    (bsc#985609).

  - CVE-2015-8918: Overlapping memcpy in CAB parser
    (bsc#985698).

  - CVE-2015-2304: Reject absolute paths in input mode of
    bsdcpio exactly when '..' is rejected (bsc#920870).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985698"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2304.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8918.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8920.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8921.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8924.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8929.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4809.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161939-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9689b08e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Studio Onsite 1.3:zypper in -t patch slestso13-bsdtar-12672=1

SUSE OpenStack Cloud 5:zypper in -t patch sleclo50sp3-bsdtar-12672=1

SUSE Manager Proxy 2.1:zypper in -t patch slemap21-bsdtar-12672=1

SUSE Manager 2.1:zypper in -t patch sleman21-bsdtar-12672=1

SUSE Linux Enterprise Software Development Kit 11-SP4:zypper in -t
patch sdksp4-bsdtar-12672=1

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-bsdtar-12672=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-bsdtar-12672=1

SUSE Linux Enterprise Server 11-SP2-LTSS:zypper in -t patch
slessp2-bsdtar-12672=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-bsdtar-12672=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-bsdtar-12672=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libarchive2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/02");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2/3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"libarchive2-2.5.5-9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libarchive2-2.5.5-9.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"libarchive2-2.5.5-9.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bsdtar");
}
