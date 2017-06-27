#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0811 and 
# CentOS Errata and Security Advisory 2010:0811 respectively.
#

include("compat.inc");

if (description)
{
  script_id(50802);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/28 23:54:24 $");

  script_cve_id("CVE-2010-2431", "CVE-2010-2941");
  script_bugtraq_id(41131);
  script_osvdb_id(65698, 68951);
  script_xref(name:"RHSA", value:"2010:0811");

  script_name(english:"CentOS 5 : cups (CESA-2010:0811)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fix two security issues are now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for UNIX operating systems.

A use-after-free flaw was found in the way the CUPS server parsed
Internet Printing Protocol (IPP) packets. A malicious user able to
send IPP requests to the CUPS server could use this flaw to crash the
CUPS server or, potentially, execute arbitrary code with the
privileges of the CUPS server. (CVE-2010-2941)

A possible privilege escalation flaw was found in CUPS. An
unprivileged process running as the 'lp' user (such as a compromised
external filter program spawned by the CUPS server) could trick the
CUPS server into overwriting arbitrary files as the root user.
(CVE-2010-2431)

Red Hat would like to thank Emmanuel Bouillon of NATO C3 Agency for
reporting the CVE-2010-2941 issue.

Users of cups are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
this update, the cupsd daemon will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-November/017135.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a833e60"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-November/017136.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f0521f8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"cups-1.3.7-18.el5_5.8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-devel-1.3.7-18.el5_5.8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-libs-1.3.7-18.el5_5.8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-lpd-1.3.7-18.el5_5.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
