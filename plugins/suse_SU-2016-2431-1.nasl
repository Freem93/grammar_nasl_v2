#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2431-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93860);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/27 20:24:10 $");

  script_cve_id("CVE-2016-5250", "CVE-2016-5257", "CVE-2016-5261", "CVE-2016-5270", "CVE-2016-5272", "CVE-2016-5274", "CVE-2016-5276", "CVE-2016-5277", "CVE-2016-5278", "CVE-2016-5280", "CVE-2016-5281", "CVE-2016-5284");
  script_osvdb_id(142472, 142473, 144426, 144614, 144615, 144616, 144617, 144618, 144619, 144620, 144621, 144623, 144624, 144625, 144627, 144628, 144630, 144634, 144635, 144636);

  script_name(english:"SUSE SLES11 Security Update : MozillaFirefox (SUSE-SU-2016:2431-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to 45.4.0 ESR to fix the following issues
(bsc#999701): The following security issue were fixed :

  - MFSA 2016-86/CVE-2016-5270: Heap-buffer-overflow in
    nsCaseTransformTextRunFactory::TransformString

  - MFSA 2016-86/CVE-2016-5272: Bad cast in
    nsImageGeometryMixin

  - MFSA 2016-86/CVE-2016-5276: Heap-use-after-free in
    mozilla::a11y::DocAccessible::ProcessInvalidationList

  - MFSA 2016-86/CVE-2016-5274: use-after-free in
    nsFrameManager::CaptureFrameState

  - MFSA 2016-86/CVE-2016-5277: Heap-use-after-free in
    nsRefreshDriver::Tick

  - MFSA 2016-86/CVE-2016-5278: Heap-buffer-overflow in
    nsBMPEncoder::AddImageFrame

  - MFSA 2016-86/CVE-2016-5280: Use-after-free in
    mozilla::nsTextNodeDirectionalityMap::RemoveElementFromM
    ap

  - MFSA 2016-86/CVE-2016-5281: use-after-free in
    DOMSVGLength

  - MFSA 2016-86/CVE-2016-5284: Add-on update site
    certificate pin expiration

  - MFSA 2016-86/CVE-2016-5250: Resource Timing API is
    storing resources sent by the previous page

  - MFSA 2016-86/CVE-2016-5261: Integer overflow and memory
    corruption in WebSocketChannel

  - MFSA 2016-86/CVE-2016-5257: Various memory safety bugs
    fixed in Firefox 49 and Firefox ESR 45.4

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5250.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5257.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5261.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5270.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5272.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5274.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5276.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5277.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5278.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5280.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5281.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5284.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162431-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ea7aa98"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS:zypper in -t patch
slessp2-MozillaFirefox-12771=1

SUSE Linux Enterprise Debuginfo 11-SP2:zypper in -t patch
dbgsp2-MozillaFirefox-12771=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/05");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-45.4.0esr-52.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-translations-45.4.0esr-52.1")) flag++;


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
