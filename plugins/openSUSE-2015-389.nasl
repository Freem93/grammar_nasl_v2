#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-389.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(83914);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/07/19 04:39:47 $");

  script_cve_id("CVE-2015-2575");

  script_name(english:"openSUSE Security Update : mysql-connector-java (openSUSE-2015-389)");
  script_summary(english:"Check for the openSUSE-2015-389 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"mysql-connector-java was updated to 5.1.35 to fix one security issue
and a number of bugs.

The following vulnerability was fixed :

  - CVE-2015-2575: Difficult to exploit vulnerability allows
    successful authenticated network attacks via multiple
    protocols. Successful attack of this vulnerability can
    result in unauthorized update, insert or delete access
    to some MySQL Connectors accessible data as well as read
    access to a subset of MySQL Connectors accessible data.

In addition, mysql-connector-java was updated to 5.1.35 to fix a
number of upstream bugs, details of which listed in CHANGES as well as
http://dev.mysql.com/doc/relnotes/connector-j/en/news-5-1.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://dev.mysql.com/doc/relnotes/connector-j/en/news-5-1.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927981"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mysql-connector-java package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mysql-connector-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"mysql-connector-java-5.1.35-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"mysql-connector-java-5.1.35-3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mysql-connector-java");
}
