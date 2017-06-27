#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:639 and 
# CentOS Errata and Security Advisory 2005:639 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21954);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/06/28 23:40:39 $");

  script_cve_id("CVE-2005-1852", "CVE-2005-2369", "CVE-2005-2370", "CVE-2005-2448");
  script_osvdb_id(18124);
  script_xref(name:"RHSA", value:"2005:639");

  script_name(english:"CentOS 4 : kdenetwork (CESA-2005:639)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdenetwork packages to correct a security flaw in Kopete are
now available for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

The kdenetwork package contains networking applications for the K
Desktop Environment. Kopete is a KDE instant messenger which supports
a number of protocols including ICQ, MSN, Yahoo, Jabber, and
Gadu-Gadu.

Multiple integer overflow flaws were found in the way Kopete processes
Gadu-Gadu messages. A remote attacker could send a specially crafted
Gadu-Gadu message which would cause Kopete to crash or possibly
execute arbitrary code. The Common Vulnerabilities and Exposures
project assigned the name CVE-2005-1852 to this issue.

In order to be affected by this issue, a user would need to have
registered with Gadu-Gadu and be signed in to the Gadu-Gadu server in
order to receive a malicious message. In addition, Red Hat believes
that the Exec-shield technology (enabled by default in Red Hat
Enterprise Linux 4) would block attempts to remotely exploit this
vulnerability.

Note that this issue does not affect Red Hat Enterprise Linux 2.1 or
3.

Users of Kopete should update to these packages which contain a patch
to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011946.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d6a2bfb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011959.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9c8a9376"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011960.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d9a7a78"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdenetwork packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdenetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdenetwork-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdenetwork-nowlistening");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"kdenetwork-3.3.1-2.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kdenetwork-devel-3.3.1-2.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kdenetwork-nowlistening-3.3.1-2.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
