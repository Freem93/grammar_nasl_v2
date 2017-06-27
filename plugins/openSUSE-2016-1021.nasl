#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1021.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93212);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/21 14:22:37 $");

  script_cve_id("CVE-2016-6606", "CVE-2016-6607", "CVE-2016-6608", "CVE-2016-6609", "CVE-2016-6610", "CVE-2016-6611", "CVE-2016-6612", "CVE-2016-6613", "CVE-2016-6614", "CVE-2016-6615", "CVE-2016-6616", "CVE-2016-6617", "CVE-2016-6618", "CVE-2016-6619", "CVE-2016-6620", "CVE-2016-6621", "CVE-2016-6622", "CVE-2016-6623", "CVE-2016-6624", "CVE-2016-6625", "CVE-2016-6626", "CVE-2016-6627", "CVE-2016-6628", "CVE-2016-6629", "CVE-2016-6630", "CVE-2016-6631", "CVE-2016-6632", "CVE-2016-6633");

  script_name(english:"openSUSE Security Update : phpMyAdmin (openSUSE-2016-1021)");
  script_summary(english:"Check for the openSUSE-2016-1021 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"phpMyAdmin was updated to version 4.4.15.8 (2016-08-16) to fix the
following issues :

  - Upstream changelog for 4.4.15.8 :

  - Improve session cookie code for openid.php and
    signon.php example files

  - Full path disclosure in openid.php and signon.php
    example files

  - Unsafe generation of BlowfishSecret (when not supplied
    by the user)

  - Referrer leak when phpinfo is enabled

  - Use HTTPS for wiki links

  - Improve SSL certificate handling

  - Fix full path disclosure in debugging code

  - Administrators could trigger SQL injection attack
    against users

  - other fixes

  - Remove Swekey support

  - Security fixes: https://www.phpmyadmin.net/security/

  - Weaknesses with cookie encryption see PMASA-2016-29
    (CVE-2016-6606, CWE-661)

  - Multiple XSS vulnerabilities see PMASA-2016-30
    (CVE-2016-6607, CWE-661)

  - Multiple XSS vulnerabilities see PMASA-2016-31
    (CVE-2016-6608, CWE-661)

  - PHP code injection see PMASA-2016-32 (CVE-2016-6609,
    CWE-661)

  - Full path disclosure see PMASA-2016-33 (CVE-2016-6610,
    CWE-661)

  - SQL injection attack see PMASA-2016-34 (CVE-2016-6611,
    CWE-661)

  - Local file exposure through LOAD DATA LOCAL INFILE see
    PMASA-2016-35 (CVE-2016-6612, CWE-661)

  - Local file exposure through symlinks with UploadDir see
    PMASA-2016-36 (CVE-2016-6613, CWE-661)

  - Path traversal with SaveDir and UploadDir see
    PMASA-2016-37 (CVE-2016-6614, CWE-661)

  - Multiple XSS vulnerabilities see PMASA-2016-38
    (CVE-2016-6615, CWE-661)

  - SQL injection vulnerability as control user see
    PMASA-2016-39 (CVE-2016-6616, CWE-661)

  - SQL injection vulnerability see PMASA-2016-40
    (CVE-2016-6617, CWE-661)

  - Denial-of-service attack through transformation feature
    see PMASA-2016-41 (CVE-2016-6618, CWE-661)

  - SQL injection vulnerability as control user see
    PMASA-2016-42 (CVE-2016-6619, CWE-661)

  - Verify data before unserializing see PMASA-2016-43
    (CVE-2016-6620, CWE-661)

  - SSRF in setup script see PMASA-2016-44 (CVE-2016-6621,
    CWE-661)

  - Denial-of-service attack with
    $cfg['AllowArbitraryServer'] = true and persistent
    connections see PMASA-2016-45 (CVE-2016-6622, CWE-661)

  - Denial-of-service attack by using for loops see
    PMASA-2016-46 (CVE-2016-6623, CWE-661)

  - Possible circumvention of IP-based allow/deny rules with
    IPv6 and proxy server see PMASA-2016-47 (CVE-2016-6624,
    CWE-661)

  - Detect if user is logged in see PMASA-2016-48
    (CVE-2016-6625, CWE-661)

  - Bypass URL redirection protection see PMASA-2016-49
    (CVE-2016-6626, CWE-661)

  - Referrer leak see PMASA-2016-50 (CVE-2016-6627, CWE-661)

  - Reflected File Download see PMASA-2016-51
    (CVE-2016-6628, CWE-661)

  - ArbitraryServerRegexp bypass see PMASA-2016-52
    (CVE-2016-6629, CWE-661)

  - Denial-of-service attack by entering long password see
    PMASA-2016-53 (CVE-2016-6630, CWE-661)

  - Remote code execution vulnerability when running as CGI
    see PMASA-2016-54 (CVE-2016-6631, CWE-661)

  - Denial-of-service attack when PHP uses dbase extension
    see PMASA-2016-55 (CVE-2016-6632, CWE-661)

  - Remove tode execution vulnerability when PHP uses dbase
    extension see PMASA-2016-56 (CVE-2016-6633, CWE-661)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.phpmyadmin.net/security/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/30");
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

if ( rpm_check(release:"SUSE13.2", reference:"phpMyAdmin-4.4.15.8-39.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"phpMyAdmin-4.4.15.8-25.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
