#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0270 and 
# CentOS Errata and Security Advisory 2008:0270 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(32326);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-1419", "CVE-2008-1420", "CVE-2008-1423");
  script_bugtraq_id(29206);
  script_osvdb_id(45155, 45156, 45157);
  script_xref(name:"RHSA", value:"2008:0270");

  script_name(english:"CentOS 3 / 4 / 5 : libvorbis (CESA-2008:0270)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvorbis packages that fix various security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The libvorbis packages contain runtime libraries for use in programs
that support Ogg Vorbis. Ogg Vorbis is a fully open, non-proprietary,
patent-and royalty-free, general-purpose compressed audio format.

Will Drewry of the Google Security Team reported several flaws in the
way libvorbis processed audio data. An attacker could create a
carefully crafted OGG audio file in such a way that it could cause an
application linked with libvorbis to crash, or execute arbitrary code
when it was opened. (CVE-2008-1419, CVE-2008-1420, CVE-2008-1423)

Moreover, additional OGG file sanity-checks have been added to prevent
possible exploitation of similar issues in the future.

Users of libvorbis are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014898.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014899.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014900.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014901.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014906.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014908.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014914.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014915.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvorbis packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvorbis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvorbis-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"libvorbis-1.0-10.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libvorbis-devel-1.0-10.el3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libvorbis-1.1.0-3.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libvorbis-1.1.0-3.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libvorbis-1.1.0-3.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libvorbis-devel-1.1.0-3.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libvorbis-devel-1.1.0-3.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libvorbis-devel-1.1.0-3.el4_6.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libvorbis-1.1.2-3.el5_1.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvorbis-devel-1.1.2-3.el5_1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
