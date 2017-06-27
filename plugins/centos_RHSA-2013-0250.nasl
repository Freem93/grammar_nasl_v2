#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0250 and 
# CentOS Errata and Security Advisory 2013:0250 respectively.
#

include("compat.inc");

if (description)
{
  script_id(64562);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/29 00:03:03 $");

  script_cve_id("CVE-2012-4545");
  script_osvdb_id(88810);
  script_xref(name:"RHSA", value:"2013:0250");

  script_name(english:"CentOS 5 / 6 : elinks (CESA-2013:0250)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated elinks package that fixes one security issue is now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

ELinks is a text-based web browser. ELinks does not display any
images, but it does support frames, tables, and most other HTML tags.

It was found that ELinks performed client credentials delegation
during the client-to-server GSS security mechanisms negotiation. A
rogue server could use this flaw to obtain the client's credentials
and impersonate that client to other servers that are using GSSAPI.
(CVE-2012-4545)

This issue was discovered by Marko Myllynen of Red Hat.

All ELinks users are advised to upgrade to this updated package, which
contains a backported patch to resolve the issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-February/019235.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e46e6401"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-February/019236.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65cc417e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected elinks package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elinks");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"elinks-0.11.1-8.el5_9")) flag++;

if (rpm_check(release:"CentOS-6", reference:"elinks-0.12-0.21.pre5.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
