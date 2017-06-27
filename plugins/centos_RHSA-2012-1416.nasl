#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1416 and 
# CentOS Errata and Security Advisory 2012:1416 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67095);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/29 00:08:47 $");

  script_cve_id("CVE-2012-4512", "CVE-2012-4513");
  script_bugtraq_id(55879);
  script_osvdb_id(86825, 86847);
  script_xref(name:"RHSA", value:"2012:1416");

  script_name(english:"CentOS 6 : kdelibs (CESA-2012:1416)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdelibs packages that fix two security issues are now
available for Red Hat Enterprise Linux 6.

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
  # http://lists.centos.org/pipermail/centos-announce/2012-October/018967.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ae5180ef"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdelibs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"kdelibs-4.3.4-14.el6_3.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kdelibs-apidocs-4.3.4-14.el6_3.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kdelibs-common-4.3.4-14.el6_3.2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kdelibs-devel-4.3.4-14.el6_3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
