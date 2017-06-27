#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0861 and 
# CentOS Errata and Security Advisory 2014:0861 respectively.
#

include("compat.inc");

if (description)
{
  script_id(76429);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2014-4607");
  script_bugtraq_id(68213);
  script_osvdb_id(108438);
  script_xref(name:"RHSA", value:"2014:0861");

  script_name(english:"CentOS 6 / 7 : lzo (CESA-2014:0861)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated lzo packages that fix one security issue are now available for
Red Hat Enterprise Linux 6 and 7.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

LZO is a portable lossless data compression library written in ANSI C.

An integer overflow flaw was found in the way the lzo library
decompressed certain archives compressed with the LZO algorithm. An
attacker could create a specially crafted LZO-compressed input that,
when decompressed by an application using the lzo library, would cause
that application to crash or, potentially, execute arbitrary code.
(CVE-2014-4607)

Red Hat would like to thank Don A. Bailey from Lab Mouse Security for
reporting this issue.

All lzo users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. For the update to
take effect, all services linked to the lzo library must be restarted
or the system rebooted."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-July/020401.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b10dd4d1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-July/020406.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5bd19ea"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected lzo packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lzo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lzo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lzo-minilzo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"lzo-2.03-3.1.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"lzo-devel-2.03-3.1.el6_5.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"lzo-minilzo-2.03-3.1.el6_5.1")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"lzo-2.06-6.el7_0.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"lzo-devel-2.06-6.el7_0.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"lzo-minilzo-2.06-6.el7_0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
