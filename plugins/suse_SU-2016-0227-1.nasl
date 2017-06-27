#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0227-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(88178);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2015-5477", "CVE-2015-5722", "CVE-2015-8000", "CVE-2015-8704");
  script_osvdb_id(125438, 126995, 131837, 133380);

  script_name(english:"SUSE SLES10 Security Update : bind (SUSE-SU-2016:0227-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for bind fixes the following issues :

CVE-2015-8000: Remote denial of service by mis-parsing incoming
responses. (bsc#958861)

CVE-2015-5722: DoS against servers performing validation on
DNSSEC-signed records. (bsc#944066)

CVE-2015-5477: DoS against authoritative and recursive servers.

CVE-2015-8704: Specific APL data could trigger a crash. (bsc#962189)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962189"
  );
  # https://download.suse.com/patch/finder/?keywords=6c9cd85bd7aa9140126fe2cf192d0ac0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fb3daf0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5722.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8704.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160227-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5f4d71c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bind packages");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-chrootenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:bind-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/26");
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
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"bind-libs-32bit-9.6ESVR11P1-0.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"bind-libs-32bit-9.6ESVR11P1-0.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"bind-9.6ESVR11P1-0.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"bind-chrootenv-9.6ESVR11P1-0.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"bind-devel-9.6ESVR11P1-0.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"bind-doc-9.6ESVR11P1-0.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"bind-libs-9.6ESVR11P1-0.18.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"bind-utils-9.6ESVR11P1-0.18.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bind");
}
