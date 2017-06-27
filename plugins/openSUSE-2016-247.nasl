#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-247.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(88922);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/02/24 16:02:12 $");

  script_name(english:"openSUSE Security Update : obs-service-download_files / obs-service-extract_file / obs-service-recompress / etc (openSUSE-2016-247)");
  script_summary(english:"Check for the openSUSE-2016-247 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for a number of source services fixes the following 
issues :

  - boo#967265: Various code/parameter injection issues
    could have allowed malicious service definition to
    execute commands or make changes to the user's file
    system

The following source services are affected

  - obs-service-source_validator

  - obs-service-extract_file

  - obs-service-download_files

  - obs-service-recompress

  - obs-service-verify_file

Also contains all bug fixes and improvements from the openSUSE:Tools
versions."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected obs-service-download_files / obs-service-extract_file / obs-service-recompress / etc packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:obs-service-download_files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:obs-service-extract_file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:obs-service-recompress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:obs-service-source_validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:obs-service-verify_file");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"obs-service-download_files-0.5.1.git.1455712026.9c0a4a0-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"obs-service-extract_file-0.3-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"obs-service-recompress-0.3.1+git20160217.7897d3f-3.3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"obs-service-source_validator-0.6+git20160218.73d6618-3.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"obs-service-verify_file-0.1.1-12.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"obs-service-download_files-0.5.1.git.1455712026.9c0a4a0-6.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"obs-service-extract_file-0.3-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"obs-service-recompress-0.3.1+git20160217.7897d3f-7.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"obs-service-source_validator-0.6+git20160218.73d6618-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"obs-service-verify_file-0.1.1-20.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "obs-service-download_files / obs-service-extract_file / etc");
}
