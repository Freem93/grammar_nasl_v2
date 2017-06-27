#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:1268 and 
# CentOS Errata and Security Advisory 2017:1268 respectively.
#

include("compat.inc");

if (description)
{
  script_id(100359);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/24 13:36:53 $");

  script_cve_id("CVE-2017-8779");
  script_xref(name:"RHSA", value:"2017:1268");

  script_name(english:"CentOS 6 : libtirpc (CESA-2017:1268)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for libtirpc is now available for Red Hat Enterprise Linux
6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The libtirpc packages contain SunLib's implementation of
transport-independent remote procedure call (TI-RPC) documentation,
which includes a library required by programs in the nfs-utils and
rpcbind packages.

Security Fix(es) :

* It was found that due to the way rpcbind uses libtirpc (libntirpc),
a memory leak can occur when parsing specially crafted XDR messages.
An attacker sending thousands of messages to rpcbind could cause its
memory usage to grow without bound, eventually causing it to be
terminated by the OOM killer. (CVE-2017-8779)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2017-May/022416.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtirpc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtirpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtirpc-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"libtirpc-0.2.1-13.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libtirpc-devel-0.2.1-13.el6_9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
