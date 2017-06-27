#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-113.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74888);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/10 14:11:56 $");

  script_cve_id("CVE-2013-1618");
  script_osvdb_id(89848);

  script_name(english:"openSUSE Security Update : Opera (openSUSE-SU-2013:0289-2)");
  script_summary(english:"Check for the openSUSE-2013-113 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Opera was updated to 12.14 version fixing stability issues. This
update also consists updates for Opera 12.13 which is a recommended
upgrade offering security and stability enhancements.

-fixed an issue where Opera gets internal communication errors on
Facebook

-fixed an issue where no webpages load on startup, if Opera
is disconnected from the Internet

-fixed an issue where images will not load after back
navigation, when a site uses the HTML5 history API
(deviantart.com)

-improved protection against hijacking of the default
search, including a one-time reset

-fixed an issue where DOM events manipulation might be used
to execute arbitrary code;

-fixed an issue where use of SVG clipPaths could allow
execution of arbitrary code;

-CVE-2013-1618: Fixed a TLS information leak.

-fixed an issue where CORS requests could omit the preflight
request;"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-02/msg00038.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-02/msg00093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801233"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Opera packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opera-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"opera-12.14-38.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"opera-gtk-12.14-38.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"opera-kde4-12.14-38.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"opera-12.14-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"opera-gtk-12.14-1.12.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"opera-kde4-12.14-1.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opera / opera-gtk / opera-kde4");
}
