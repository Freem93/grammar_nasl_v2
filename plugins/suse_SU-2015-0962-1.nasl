#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0962-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83903);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2015-3143", "CVE-2015-3148", "CVE-2015-3153");
  script_bugtraq_id(74299, 74301, 74408);
  script_osvdb_id(121128, 121129, 121452);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : curl (SUSE-SU-2015:0962-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The curl tool and libcurl4 library have been updated to fix several
security and non-security issues.

The following vulnerabilities have been fixed :

CVE-2015-3143: Re-using authenticated connection when unauthenticated.
(bsc#927556)

CVE-2015-3148: Negotiate not treated as connection-oriented.
(bsc#927746)

CVE-2015-3153: Sensitive HTTP server headers also sent to proxies.
(bsc#928533)

The following non-security issue has been fixed :

git fails to clone from https repository. (bsc#927174)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927556"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928533"
  );
  # https://download.suse.com/patch/finder/?keywords=15283cac05d947363283c7ddcb466af0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?386b8563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3143.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3148.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3153.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150962-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0afcc3ad"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11 SP3 :

zypper in -t patch sdksp3-curl=10660

SUSE Linux Enterprise Server 11 SP3 for VMware :

zypper in -t patch slessp3-curl=10660

SUSE Linux Enterprise Server 11 SP3 :

zypper in -t patch slessp3-curl=10660

SUSE Linux Enterprise Desktop 11 SP3 :

zypper in -t patch sledsp3-curl=10660

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcurl4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"libcurl4-32bit-7.19.7-1.42.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"libcurl4-32bit-7.19.7-1.42.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"curl-7.19.7-1.42.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"libcurl4-7.19.7-1.42.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"curl-7.19.7-1.42.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libcurl4-7.19.7-1.42.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"libcurl4-32bit-7.19.7-1.42.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"curl-7.19.7-1.42.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"libcurl4-7.19.7-1.42.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl");
}
