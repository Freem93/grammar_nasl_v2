#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-112.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75250);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-6480");

  script_name(english:"openSUSE Security Update : python-apache-libcloud (openSUSE-SU-2014:0198-1)");
  script_summary(english:"Check for the openSUSE-2014-112 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Updated to 0.13.3 (bnc#857209, CVE-2013-6480)

  + Security fix release, for destroying nodes on
    digitalOcean 'data_scrub' method is always invoked

  - Require python-setuptools instead of distribute
    (upstreams merged)

  - Updated to 0.13.2

  - General :

  - Don't sent Content-Length: 0 header with POST and PUT
    request if 'raw' mode is used. This fixes a regression
    which could cause broken behavior in some storage driver
    when uploading a file from disk.

  - Compute :

  - Added Ubuntu Linux 12.04 image to ElasticHost driver
    image list. (LIBCLOUD-364)

  - Update ElasticHosts driver to store drive UUID in the
    node 'extra' field. (LIBCLOUD-357)

  - Storage :

  - Store last_modified timestamp in the Object extra
    dictionary in the S3 driver. (LIBCLOUD-373)

  - Load Balancer :

  - Expose CloudStack driver directly through the
    Provider.CLOUDSTACK constant.

  - DNS :

  - Modify Zerigo driver to include record TTL in the record
    'extra' attribute if a record has a TTL set.

  - Modify values in the Record 'extra' dictionary attribute
    in the Zerigo DNS driver to be set to None instead of an
    empty string ('') if a value for the provided key is not
    set."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-02/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=857209"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-apache-libcloud package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-apache-libcloud");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"python-apache-libcloud-0.13.3-2.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-apache-libcloud");
}
