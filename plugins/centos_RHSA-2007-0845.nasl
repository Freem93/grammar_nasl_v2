#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0845 and 
# CentOS Errata and Security Advisory 2007:0845 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(26073);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-3106", "CVE-2007-4029", "CVE-2007-4065", "CVE-2007-4066");
  script_bugtraq_id(25082);
  script_osvdb_id(38675, 38676, 38677, 38678, 38679);
  script_xref(name:"RHSA", value:"2007:0845");

  script_name(english:"CentOS 3 / 4 / 5 : libvorbis (CESA-2007:0845)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libvorbis packages to correct several security issues are now
available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The libvorbis package contains runtime libraries for use in programs
that support Ogg Voribs. Ogg Vorbis is a fully open, non-proprietary,
patent-and royalty-free, general-purpose compressed audio format.

Several flaws were found in the way libvorbis processed audio data. An
attacker could create a carefully crafted OGG audio file in such a way
that it could cause an application linked with libvorbis to crash or
execute arbitrary code when it was opened. (CVE-2007-3106,
CVE-2007-4029, CVE-2007-4065, CVE-2007-4066)

Users of libvorbis are advised to upgrade to this updated package,
which contains backported patches that resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014205.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?318e79d5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014206.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33761332"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014209.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?560c491e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014211.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?038abf6c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014221.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a8948f8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014222.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b3532e7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014225.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aaccbf3a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014226.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95fcb679"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libvorbis packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvorbis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libvorbis-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"libvorbis-1.0-8.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libvorbis-devel-1.0-8.el3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"libvorbis-1.1.0-2.el4.5")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libvorbis-devel-1.1.0-2.el4.5")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libvorbis-1.1.2-3.el5.0")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libvorbis-devel-1.1.2-3.el5.0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
