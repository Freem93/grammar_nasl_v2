#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0577 and 
# CentOS Errata and Security Advisory 2006:0577 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22039);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-3242");
  script_osvdb_id(26814);
  script_xref(name:"RHSA", value:"2006:0577");

  script_name(english:"CentOS 3 / 4 : mutt (CESA-2006:0577)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mutt packages that fix a security issue are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Mutt is a text-mode mail user agent.

A buffer overflow flaw was found in the way Mutt processes an overly
long namespace from a malicious imap server. In order to exploit this
flaw a user would have to use Mutt to connect to a malicious IMAP
server. (CVE-2006-3242)

Users of Mutt are advised to upgrade to these erratum packages, which
contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013001.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bbdd24ca"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013005.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?441e0b53"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013010.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16296045"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013011.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7f7b98c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013018.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0575eb9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013019.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3fd3d9af"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected mutt package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mutt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/19");
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
if (rpm_check(release:"CentOS-3", reference:"mutt-1.4.1-3.5.rhel3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"mutt-1.4.1-11.rhel4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
