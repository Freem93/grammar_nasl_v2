#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0500 and 
# CentOS Errata and Security Advisory 2006:0500 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22064);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2006-0747", "CVE-2006-1861", "CVE-2006-2661", "CVE-2006-3467");
  script_osvdb_id(27255, 34169, 34170);
  script_xref(name:"RHSA", value:"2006:0500");

  script_name(english:"CentOS 3 / 4 : freetype (CESA-2006:0500)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freetype packages that fix several security flaws are now
available for Red Hat Enterprise Linux.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

FreeType is a free, high-quality, and portable font engine.

Chris Evans discovered several integer underflow and overflow flaws in
the FreeType font engine. If a user loads a carefully crafted font
file with a program linked against FreeType, it could cause the
application to crash or execute arbitrary code as the user. While it
is uncommon for a user to explicitly load a font file, there are
several application file formats which contain embedded fonts that are
parsed by FreeType. (CVE-2006-0747, CVE-2006-1861, CVE-2006-3467)

A NULL pointer dereference flaw was found in the FreeType font engine.
An application linked against FreeType can crash upon loading a
malformed font file. (CVE-2006-2661)

Users of FreeType should upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013023.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b9e9e3e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013026.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b605ace7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013042.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a6b4524"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013043.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e329ccfa"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013060.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?87a7438c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013061.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2aa8f332"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected freetype packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:freetype-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"freetype-2.1.4-4.0.rhel3.2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"freetype-demos-2.1.4-4.0.rhel3.2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"freetype-devel-2.1.4-4.0.rhel3.2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"freetype-devel-2.1.4-4.0.rhel3.2")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"freetype-utils-2.1.4-4.0.rhel3.2")) flag++;

if (rpm_check(release:"CentOS-4", reference:"freetype-2.1.9-1.rhel4.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"freetype-demos-2.1.9-1.rhel4.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"freetype-devel-2.1.9-1.rhel4.4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"freetype-utils-2.1.9-1.rhel4.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
