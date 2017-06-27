#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0005 and 
# CentOS Errata and Security Advisory 2016:0005 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87778);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2015-7236");
  script_osvdb_id(127773);
  script_xref(name:"RHSA", value:"2016:0005");

  script_name(english:"CentOS 6 / 7 : rpcbind (CESA-2016:0005)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated rpcbind packages that fix one security issue are now available
for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The rpcbind utility is a server that converts RPC program numbers into
universal addresses. It must be running on the host to be able to make
RPC calls on a server on that machine.

A use-after-free flaw related to the PMAP_CALLIT operation and TCP/UDP
connections was discovered in rpcbind. A remote attacker could
possibly exploit this flaw to crash the rpcbind service by performing
a series of UDP and TCP calls. (CVE-2015-7236)

All rpcbind users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. If the rpcbind
service is running, it will be automatically restarted after
installing this update."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-January/021593.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9e708b7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-January/021604.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b15ac654"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected rpcbind package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:rpcbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"rpcbind-0.2.0-11.el6_7")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"rpcbind-0.2.0-33.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
