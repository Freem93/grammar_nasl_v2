#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0880 and 
# Oracle Linux Security Advisory ELSA-2012-0880 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68557);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 17:07:15 $");

  script_cve_id("CVE-2010-5076", "CVE-2011-3922");
  script_bugtraq_id(42833, 51300);
  script_osvdb_id(68079, 78150);
  script_xref(name:"RHSA", value:"2012:0880");

  script_name(english:"Oracle Linux 6 : qt (ELSA-2012-0880)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0880 :

Updated qt packages that fix two security issues and three bugs are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Qt is a software toolkit that simplifies the task of writing and
maintaining GUI (Graphical User Interface) applications for the X
Window System. HarfBuzz is an OpenType text shaping engine.

A buffer overflow flaw was found in the harfbuzz module in Qt. If a
user loaded a specially crafted font file with an application linked
against Qt, it could cause the application to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2011-3922)

A flaw was found in the way Qt handled X.509 certificates with IP
address wildcards. An attacker able to obtain a certificate with a
Common Name containing an IP wildcard could possibly use this flaw to
impersonate an SSL server to client applications that are using Qt.
This update also introduces more strict handling for hostname wildcard
certificates by disallowing the wildcard character to match more than
one hostname component. (CVE-2010-5076)

This update also fixes the following bugs :

* The Phonon API allowed premature freeing of the media object.
Consequently, GStreamer could terminate unexpectedly as it failed to
access the released media object. This update modifies the underlying
Phonon API code and the problem no longer occurs. (BZ#694684)

* Previously, Qt could output the 'Unrecognized OpenGL version' error
and fall back to OpenGL-version-1 compatibility mode. This happened
because Qt failed to recognize the version of OpenGL installed on the
system if the system was using a version of OpenGL released later than
the Qt version in use. This update adds the code for recognition of
OpenGL versions to Qt and if the OpenGL version is unknown, Qt assumes
that the last-known version of OpenGL is available. (BZ#757793)

* Previously Qt included a compiled-in list of trusted CA (Certificate
Authority) certificates, that could have been used if Qt failed to
open a system's ca-bundle.crt file. With this update, Qt no longer
includes compiled-in CA certificates and only uses the system bundle.
(BZ#734444)

Users of Qt should upgrade to these updated packages, which contain
backported patches to correct these issues. All running applications
linked against Qt libraries must be restarted for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-July/002908.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected qt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:phonon-backend-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:qt-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL6", reference:"phonon-backend-gstreamer-4.6.2-24.el6")) flag++;
if (rpm_check(release:"EL6", reference:"qt-4.6.2-24.el6")) flag++;
if (rpm_check(release:"EL6", reference:"qt-demos-4.6.2-24.el6")) flag++;
if (rpm_check(release:"EL6", reference:"qt-devel-4.6.2-24.el6")) flag++;
if (rpm_check(release:"EL6", reference:"qt-doc-4.6.2-24.el6")) flag++;
if (rpm_check(release:"EL6", reference:"qt-examples-4.6.2-24.el6")) flag++;
if (rpm_check(release:"EL6", reference:"qt-mysql-4.6.2-24.el6")) flag++;
if (rpm_check(release:"EL6", reference:"qt-odbc-4.6.2-24.el6")) flag++;
if (rpm_check(release:"EL6", reference:"qt-postgresql-4.6.2-24.el6")) flag++;
if (rpm_check(release:"EL6", reference:"qt-sqlite-4.6.2-24.el6")) flag++;
if (rpm_check(release:"EL6", reference:"qt-x11-4.6.2-24.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phonon-backend-gstreamer / qt / qt-demos / qt-devel / qt-doc / etc");
}
