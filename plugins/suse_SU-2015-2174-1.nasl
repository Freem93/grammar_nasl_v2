#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:2174-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(87199);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_osvdb_id(118467, 118468);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : dhcpcd (SUSE-SU-2015:2174-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"dhcpcd was updated to fix one security issue.

This security issue was fixed :

  - A missing length check in decode_search could have
    caused DOS (bsc#955762).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955762"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20152174-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd814fe4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-dhcpcd-12241=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-dhcpcd-12241=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-dhcpcd-12241=1

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-dhcpcd-12241=1

SUSE Linux Enterprise Desktop 11-SP4 :

zypper in -t patch sledsp4-dhcpcd-12241=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-dhcpcd-12241=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-dhcpcd-12241=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-dhcpcd-12241=1

SUSE Linux Enterprise Debuginfo 11-SP2 :

zypper in -t patch dbgsp2-dhcpcd-12241=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dhcpcd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/04");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(2|3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2/3/4", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"dhcpcd-3.2.3-44.32.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"dhcpcd-3.2.3-44.32.2")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"dhcpcd-3.2.3-44.32.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"x86_64", reference:"dhcpcd-3.2.3-44.32.2")) flag++;
if (rpm_check(release:"SLED11", sp:"4", cpu:"i586", reference:"dhcpcd-3.2.3-44.32.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"dhcpcd-3.2.3-44.32.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"dhcpcd-3.2.3-44.32.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcpcd");
}
