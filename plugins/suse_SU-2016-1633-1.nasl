#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1633-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93160);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2013-7456", "CVE-2015-8876", "CVE-2015-8877", "CVE-2015-8879", "CVE-2016-5093", "CVE-2016-5094", "CVE-2016-5095", "CVE-2016-5096");
  script_osvdb_id(125853, 125858, 138956, 138996, 138997, 139004, 139005);

  script_name(english:"SUSE SLED12 Security Update : php5 (SUSE-SU-2016:1633-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for php5 fixes the following issues :

  - CVE-2013-7456: imagescale out-of-bounds read
    (bnc#982009).

  - CVE-2016-5093: get_icu_value_internal out-of-bounds read
    (bnc#982010).

  - CVE-2016-5094: Don't create strings with lengths outside
    of valid range (bnc#982011).

  - CVE-2016-5095: Don't create strings with lengths outside
    of valid range (bnc#982012).

  - CVE-2016-5096: int/size_t confusion in fread
    (bsc#982013).

  - CVE-2015-8877: The gdImageScaleTwoPass function in
    gd_interpolation.c in the GD Graphics Library (aka
    libgd) as used in PHP used inconsistent allocate and
    free approaches, which allowed remote attackers to cause
    a denial of service (memory consumption) via a crafted
    call, as demonstrated by a call to the PHP imagescale
    function (bsc#981061).

  - CVE-2015-8876: Zend/zend_exceptions.c in PHP did not
    validate certain Exception objects, which allowed remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) or trigger unintended
    method execution via crafted serialized data
    (bsc#981049).

  - CVE-2015-8879: The odbc_bindcols function in
    ext/odbc/php_odbc.c in PHP mishandles driver behavior
    for SQL_WVARCHAR columns, which allowed remote attackers
    to cause a denial of service (application crash) in
    opportunistic circumstances by leveraging use of the
    odbc_fetch_array function to access a certain type of
    Microsoft SQL Server table (bsc#981050).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-7456.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8876.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8877.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8879.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5094.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5095.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5096.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161633-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eed6abc1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1 :

zypper in -t patch SUSE-SLE-WE-12-SP1-2016-968=1

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2016-968=1

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-968=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-968=1

SUSE Linux Enterprise Module for Web Scripting 12 :

zypper in -t patch SUSE-SLE-Module-Web-Scripting-12-2016-968=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-968=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-968=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:imap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:imap-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libc-client2007e_suse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libc-client2007e_suse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/20");
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
if (! ereg(pattern:"^(SLED12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED12" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"imap-debuginfo-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"imap-debugsource-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libc-client2007e_suse-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"libc-client2007e_suse-debuginfo-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"imap-debuginfo-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"imap-debugsource-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libc-client2007e_suse-2007e_suse-19.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libc-client2007e_suse-debuginfo-2007e_suse-19.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php5");
}
