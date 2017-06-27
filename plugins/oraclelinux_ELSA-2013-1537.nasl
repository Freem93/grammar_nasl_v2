#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:1537 and 
# Oracle Linux Security Advisory ELSA-2013-1537 respectively.
#

include("compat.inc");

if (description)
{
  script_id(71102);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 17:02:15 $");

  script_cve_id("CVE-2012-0786", "CVE-2012-0787", "CVE-2012-6607");
  script_bugtraq_id(63861);
  script_osvdb_id(100076);
  script_xref(name:"RHSA", value:"2013:1537");

  script_name(english:"Oracle Linux 6 : augeas (ELSA-2013-1537)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:1537 :

Updated augeas packages that fix two security issues, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Augeas is a utility for editing configuration. Augeas parses
configuration files in their native formats and transforms them into a
tree. Configuration changes are made by manipulating this tree and
saving it back into native configuration files. Augeas also uses
'lenses' as basic building blocks for establishing the mapping from
files into the Augeas tree and back.

Multiple flaws were found in the way Augeas handled configuration
files when updating them. An application using Augeas to update
configuration files in a directory that is writable to by a different
user (for example, an application running as root that is updating
files in a directory owned by a non-root service user) could have been
tricked into overwriting arbitrary files or leaking information via a
symbolic link or mount point attack. (CVE-2012-0786, CVE-2012-0787)

The augeas package has been upgraded to upstream version 1.0.0, which
provides a number of bug fixes and enhancements over the previous
version. (BZ#817753)

This update also fixes the following bugs :

* Previously, when single quotes were used in an XML attribute, Augeas
was unable to parse the file with the XML lens. An upstream patch has
been provided ensuring that single quotes are handled as valid
characters and parsing no longer fails. (BZ#799885)

* Prior to this update, Augeas was unable to set up the
'require_ssl_reuse' option in the vsftpd.conf file. The updated patch
fixes the vsftpd lens to properly recognize this option, thus fixing
this bug. (BZ#855022)

* Previously, the XML lens did not support non-Unix line endings.
Consequently, Augeas was unable to load any files containing such line
endings. The XML lens has been fixed to handle files with CRLF line
endings, thus fixing this bug. (BZ#799879)

* Previously, Augeas was unable to parse modprobe.conf files with
spaces around '=' characters in option directives. The modprobe lens
has been updated and parsing no longer fails. (BZ#826752)

All Augeas users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-November/003803.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected augeas packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:augeas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:augeas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:augeas-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"augeas-1.0.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"augeas-devel-1.0.0-5.el6")) flag++;
if (rpm_check(release:"EL6", reference:"augeas-libs-1.0.0-5.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "augeas / augeas-devel / augeas-libs");
}
