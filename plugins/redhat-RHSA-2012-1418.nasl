#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1418. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62772);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/05/02 20:36:57 $");

  script_cve_id("CVE-2012-4512", "CVE-2012-4513");
  script_xref(name:"RHSA", value:"2012:1418");

  script_name(english:"RHEL 6 : kdelibs (RHSA-2012:1418)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdelibs packages that fix two security issues are now
available for Red Hat Enterprise Linux 6 FasTrack.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kdelibs packages provide libraries for the K Desktop Environment
(KDE). Konqueror is a web browser.

A heap-based buffer overflow flaw was found in the way the CSS
(Cascading Style Sheets) parser in kdelibs parsed the location of the
source for font faces. A web page containing malicious content could
cause an application using kdelibs (such as Konqueror) to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2012-4512)

A heap-based buffer over-read flaw was found in the way kdelibs
calculated canvas dimensions for large images. A web page containing
malicious content could cause an application using kdelibs to crash or
disclose portions of its memory. (CVE-2012-4513)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The desktop must be
restarted (log out, then log back in) for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4512.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4513.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.redhat.com/rhn/rhndetails/fastrack/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1418.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL6", reference:"kdelibs-4.3.4-19.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"kdelibs-apidocs-4.3.4-19.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kdelibs-common-4.3.4-19.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kdelibs-common-4.3.4-19.el6")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kdelibs-common-4.3.4-19.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"kdelibs-debuginfo-4.3.4-19.el6")) flag++;
if (rpm_check(release:"RHEL6", reference:"kdelibs-devel-4.3.4-19.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
