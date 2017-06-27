#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0094 and 
# CentOS Errata and Security Advisory 2010:0094 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44428);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/08/17 04:30:01 $");

  script_cve_id("CVE-2009-4242", "CVE-2009-4245", "CVE-2009-4247", "CVE-2009-4248", "CVE-2009-4257", "CVE-2010-0416", "CVE-2010-0417");
  script_bugtraq_id(37880);
  script_osvdb_id(61969, 61972, 62469, 62470, 62471);
  script_xref(name:"RHSA", value:"2010:0094");
  script_xref(name:"IAVA", value:"2010-A-0022");

  script_name(english:"CentOS 4 : HelixPlayer (CESA-2010:0094)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated HelixPlayer package that fixes several security issues is
now available for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

HelixPlayer is a media player.

Multiple buffer and integer overflow flaws were found in the way
HelixPlayer processed Graphics Interchange Format (GIF) files. An
attacker could create a specially crafted GIF file which would cause
HelixPlayer to crash or, potentially, execute arbitrary code when
opened. (CVE-2009-4242, CVE-2009-4245)

A buffer overflow flaw was found in the way HelixPlayer processed
Synchronized Multimedia Integration Language (SMIL) files. An attacker
could create a specially crafted SMIL file which would cause
HelixPlayer to crash or, potentially, execute arbitrary code when
opened. (CVE-2009-4257)

A buffer overflow flaw was found in the way HelixPlayer handled the
Real Time Streaming Protocol (RTSP) SET_PARAMETER directive. A
malicious RTSP server could use this flaw to crash HelixPlayer or,
potentially, execute arbitrary code. (CVE-2009-4248)

Multiple buffer overflow flaws were discovered in the way HelixPlayer
handled RuleBook structures in media files and RTSP streams. Specially
crafted input could cause HelixPlayer to crash or, potentially,
execute arbitrary code. (CVE-2009-4247, CVE-2010-0417)

A buffer overflow flaw was found in the way HelixPlayer performed URL
un-escaping. A specially crafted URL string could cause HelixPlayer to
crash or, potentially, execute arbitrary code. (CVE-2010-0416)

All HelixPlayer users are advised to upgrade to this updated package,
which contains backported patches to resolve these issues. All running
instances of HelixPlayer must be restarted for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-February/016495.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7035b66c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-February/016496.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1121869"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected helixplayer package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:HelixPlayer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/10");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"HelixPlayer-1.0.6-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"HelixPlayer-1.0.6-1.el4_8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
