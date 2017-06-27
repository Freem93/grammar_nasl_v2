#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0267 and 
# CentOS Errata and Security Advisory 2006:0267 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21894);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-3666", "CVE-2005-3667", "CVE-2005-3668", "CVE-2005-3732");
  script_osvdb_id(61003);
  script_xref(name:"RHSA", value:"2006:0267");

  script_name(english:"CentOS 3 / 4 : ipsec-tools (CESA-2006:0267)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ipsec-tools packages that fix a bug in racoon are now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The ipsec-tools package is used in conjunction with the IPsec
functionality in the linux kernel and includes racoon, an IKEv1 keying
daemon.

A denial of service flaw was found in the ipsec-tools racoon daemon.
If a victim's machine has racoon configured in a non-recommended
insecure manner, it is possible for a remote attacker to crash the
racoon daemon. (CVE-2005-3732)

Users of ipsec-tools should upgrade to these updated packages, which
contain backported patches, and are not vulnerable to these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012840.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32f9d08c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012841.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbfe38f5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012844.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9475e14"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012847.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10d1873f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012850.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1be00183"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012851.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41934b15"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ipsec-tools package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipsec-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"ipsec-tools-0.2.5-0.7.rhel3.3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"ipsec-tools-0.3.3-6.rhel4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
