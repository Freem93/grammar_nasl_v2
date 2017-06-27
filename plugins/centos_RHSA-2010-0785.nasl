#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0785 and 
# CentOS Errata and Security Advisory 2010:0785 respectively.
#

include("compat.inc");

if (description)
{
  script_id(50794);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/04 14:30:42 $");

  script_cve_id("CVE-2007-4826", "CVE-2010-2948");
  script_bugtraq_id(25634, 42635);
  script_osvdb_id(67394);
  script_xref(name:"RHSA", value:"2010:0785");

  script_name(english:"CentOS 4 / 5 : quagga (CESA-2010:0785)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated quagga packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Quagga is a TCP/IP based routing software suite. The Quagga bgpd
daemon implements the BGP (Border Gateway Protocol) routing protocol.

A stack-based buffer overflow flaw was found in the way the Quagga
bgpd daemon processed certain BGP Route Refresh (RR) messages. A
configured BGP peer could send a specially crafted BGP message,
causing bgpd on a target system to crash or, possibly, execute
arbitrary code with the privileges of the user running bgpd.
(CVE-2010-2948)

Note: On Red Hat Enterprise Linux 5 it is not possible to exploit
CVE-2010-2948 to run arbitrary code as the overflow is blocked by
FORTIFY_SOURCE.

Multiple NULL pointer dereference flaws were found in the way the
Quagga bgpd daemon processed certain specially crafted BGP messages. A
configured BGP peer could crash bgpd on a target system via specially
crafted BGP messages. (CVE-2007-4826)

Users of quagga should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the bgpd daemon must be restarted for the update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017097.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd5d9924"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017098.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?306e4cb9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017115.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eeda59b2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-October/017116.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3634a9fa"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected quagga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:quagga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:quagga-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:quagga-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"quagga-0.98.3-4.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"quagga-0.98.3-4.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"quagga-contrib-0.98.3-4.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"quagga-contrib-0.98.3-4.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"quagga-devel-0.98.3-4.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"quagga-devel-0.98.3-4.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"quagga-0.98.6-5.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"quagga-contrib-0.98.6-5.el5_5.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"quagga-devel-0.98.6-5.el5_5.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
