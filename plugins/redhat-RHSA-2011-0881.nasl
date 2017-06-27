#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0881. The text 
# itself is copyright (C) Red Hat, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63984);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/13 15:17:27 $");

  script_cve_id("CVE-2003-1564", "CVE-2011-1753", "CVE-2011-1754", "CVE-2011-1755", "CVE-2011-1756", "CVE-2011-1757", "CVE-2011-2188");
  script_bugtraq_id(48250);
  script_xref(name:"RHSA", value:"2011:0881");

  script_name(english:"RHEL 5 : jabberd (RHSA-2011:0881)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated jabberd package that fixes one security issue is now
available for Red Hat Network Proxy 5.4.1 for Red Hat Enterprise Linux
5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

This package provides jabberd 2, an Extensible Messaging and Presence
Protocol (XMPP) server used for XML based communication.

It was found that the jabberd daemon did not properly detect recursion
during entity expansion. A remote attacker could provide a
specially crafted XML file containing a large number of nested entity
references, which once processed by the jabberd daemon, could lead to
a denial of service (excessive memory and CPU consumption).
(CVE-2011-1755)

Red Hat would like to thank Nico Golde of the Debian Security Team for
reporting this issue. The Debian Security Team acknowledges Wouter
Coekaerts as the original reporter.

Users of Red Hat Network Proxy 5.4.1 are advised to upgrade to this
updated jabberd package, which resolves this issue. For this update to
take effect, Red Hat Network Proxy must be restarted. Refer to the
Solution section for details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1755.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0881.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected jabberd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jabberd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL5", cpu:"i386", reference:"jabberd-2.2.8-12.el5sat")) flag++;
if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"jabberd-2.2.8-12.el5sat")) flag++;
if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"jabberd-2.2.8-12.el5sat")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
