#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update ethereal-3885.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(27208);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/01/13 15:30:42 $");

  script_cve_id("CVE-2007-3389", "CVE-2007-3390", "CVE-2007-3391", "CVE-2007-3392", "CVE-2007-3393");

  script_name(english:"openSUSE 10 Security Update : ethereal (ethereal-3885)");
  script_summary(english:"Check for the ethereal-3885 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various security problems were fixed in the wireshark 0.99.6 release,
which were backported to ethereal (predecessor of wireshark) :

CVE-2007-3389: Wireshark allowed remote attackers to cause a denial of
service (crash) via a crafted chunked encoding in an HTTP response,
possibly related to a zero-length payload.

CVE-2007-3390: Wireshark when running on certain systems, allowed
remote attackers to cause a denial of service (crash) via crafted
iSeries capture files that trigger a SIGTRAP.

CVE-2007-3391: Wireshark allowed remote attackers to cause a denial of
service (memory consumption) via a malformed DCP ETSI packet that
triggers an infinite loop.

CVE-2007-3392: Wireshark allowed remote attackers to cause a denial of
service via malformed (1) SSL or (2) MMS packets that trigger an
infinite loop.

CVE-2007-3393: Off-by-one error in the DHCP/BOOTP dissector in
Wireshark allowed remote attackers to cause a denial of service
(crash) via crafted DHCP-over-DOCSIS packets."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ethereal packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ethereal-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"ethereal-0.10.14-16.16") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"ethereal-devel-0.10.14-16.16") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ethereal");
}
