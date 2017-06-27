#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1504-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(85868);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2015/09/29 14:15:33 $");

  script_cve_id("CVE-2015-4497", "CVE-2015-4498");
  script_osvdb_id(126767, 126768);

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox (SUSE-SU-2015:1504-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to 38.2.1 ESR, fixing two severe security
bugs. (bsc#943608)

  - MFSA 2015-94/CVE-2015-4497 (bsc#943557): Use-after-free
    when resizing canvas element during restyling

  - MFSA 2015-95/CVE-2015-4498 (bsc#943558): Add-on
    notification bypass through data URLs

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4497.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4498.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151504-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?faf3ed4f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-firefox-20150831-12071=1

SUSE Linux Enterprise Server 11-SP1-LTSS :

zypper in -t patch slessp1-firefox-20150831-12071=1

SUSE Linux Enterprise Debuginfo 11-SP2 :

zypper in -t patch dbgsp2-firefox-20150831-12071=1

SUSE Linux Enterprise Debuginfo 11-SP1 :

zypper in -t patch dbgsp1-firefox-20150831-12071=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/09");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP1/2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"1", reference:"MozillaFirefox-38.2.1esr-17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"1", reference:"MozillaFirefox-translations-38.2.1esr-17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-38.2.1esr-17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-translations-38.2.1esr-17.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
