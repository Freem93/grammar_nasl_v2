#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1708 and 
# CentOS Errata and Security Advisory 2015:1708 respectively.
#

include("compat.inc");

if (description)
{
  script_id(86506);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/10/22 14:23:03 $");

  script_cve_id("CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804");
  script_osvdb_id(119641, 119642, 119643);
  script_xref(name:"RHSA", value:"2015:1708");

  script_name(english:"CentOS 6 / 7 : libXfont (CESA-2015:1708)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated libXfont package that fixes three security issues is now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The libXfont package provides the X.Org libXfont runtime library.
X.Org is an open source implementation of the X Window System.

An integer overflow flaw was found in the way libXfont processed
certain Glyph Bitmap Distribution Format (BDF) fonts. A malicious,
local user could use this flaw to crash the X.Org server or,
potentially, execute arbitrary code with the privileges of the X.Org
server. (CVE-2015-1802)

An integer truncation flaw was discovered in the way libXfont
processed certain Glyph Bitmap Distribution Format (BDF) fonts. A
malicious, local user could use this flaw to crash the X.Org server
or, potentially, execute arbitrary code with the privileges of the
X.Org server. (CVE-2015-1804)

A NULL pointer dereference flaw was discovered in the way libXfont
processed certain Glyph Bitmap Distribution Format (BDF) fonts. A
malicious, local user could use this flaw to crash the X.Org server.
(CVE-2015-1803)

All libXfont users are advised to upgrade to this updated package,
which contains backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-September/021368.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29b71451"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-September/021371.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3b5c52b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxfont packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"libXfont-1.4.5-5.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXfont-devel-1.4.5-5.el6_7")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXfont-1.4.7-3.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXfont-devel-1.4.7-3.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
