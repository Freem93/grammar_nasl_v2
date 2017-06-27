#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0094. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64023);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/13 15:17:28 $");

  script_cve_id("CVE-2011-3256", "CVE-2011-3439");
  script_bugtraq_id(50155, 50643);
  script_xref(name:"RHSA", value:"2012:0094");

  script_name(english:"RHEL 5 : freetype (RHSA-2012:0094)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated freetype packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.6 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

FreeType is a free, high-quality, portable font engine that can open
and manage font files. It also loads, hints, and renders individual
glyphs efficiently.

Multiple input validation flaws were found in the way FreeType
processed bitmap font files. If a specially crafted font file was
loaded by an application linked against FreeType, it could cause the
application to crash or, potentially, execute arbitrary code with the
privileges of the user running the application. (CVE-2011-3256)

Multiple input validation flaws were found in the way FreeType
processed CID-keyed fonts. If a specially crafted font file was loaded
by an application linked against FreeType, it could cause the
application to crash or, potentially, execute arbitrary code with the
privileges of the user running the application. (CVE-2011-3439)

Users are advised to upgrade to these updated packages, which contain
backported patches to correct these issues. The X server must be
restarted (log out, then log back in) for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3256.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3439.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0094.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected freetype, freetype-demos and / or freetype-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freetype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freetype-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freetype-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL5", sp:"6", reference:"freetype-2.2.1-28.el5_6.1")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"freetype-demos-2.2.1-28.el5_6.1")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"freetype-demos-2.2.1-28.el5_6.1")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"freetype-demos-2.2.1-28.el5_6.1")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", reference:"freetype-devel-2.2.1-28.el5_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
