#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:363. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18108);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/05/02 17:31:16 $");

  script_cve_id("CVE-2005-0755");
  script_xref(name:"RHSA", value:"2005:363");

  script_name(english:"RHEL 4 : RealPlayer (RHSA-2005:363)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated RealPlayer package that fixes a buffer overflow issue is
now available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

RealPlayer is a media player that provides solid media playback
locally and via streaming. It plays RealAudio, RealVideo, MP3, 3GPP
Video, Flash, SMIL 2.0, JPEG, GIF, PNG, RealPix and RealText and more.

A buffer overflow bug was found in the way RealPlayer processes RAM
files. An attacker could create a specially crafted RAM file which
could execute arbitrary code when opened by a user. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-0755 to this issue.

All users of RealPlayer are advised to upgrade to this updated
package, which contains RealPlayer version 10.0.4 and is not
vulnerable to this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0755.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://service.real.com/help/faq/security/050419_player/EN/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-363.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected RealPlayer package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:RealPlayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL4", cpu:"i386", reference:"RealPlayer-10.0.4-0.rc1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
