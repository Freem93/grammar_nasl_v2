#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-786.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75174);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/09/01 13:14:19 $");

  script_cve_id("CVE-2013-2186");
  script_bugtraq_id(63174);
  script_osvdb_id(98703);
  script_xref(name:"TRA", value:"TRA-2016-23");

  script_name(english:"openSUSE Security Update : jakarta-commons-fileupload (openSUSE-SU-2013:1571-1)");
  script_summary(english:"Check for the openSUSE-2013-786 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"&#9;A remote attacker could supply a serialized instance of the
DiskFileItem class, which would be deserialized on a server and write
arbitrary content to any location on the server that is permitted by
the user running the application server process.
bnc#846174/CVE-2013-2186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-10/msg00033.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=846174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2016-23"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jakarta-commons-fileupload packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jakarta-commons-fileupload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jakarta-commons-fileupload-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"jakarta-commons-fileupload-1.1.1-112.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"jakarta-commons-fileupload-javadoc-1.1.1-112.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"jakarta-commons-fileupload-1.1.1-114.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"jakarta-commons-fileupload-javadoc-1.1.1-114.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jakarta-commons-fileupload / jakarta-commons-fileupload-javadoc");
}
