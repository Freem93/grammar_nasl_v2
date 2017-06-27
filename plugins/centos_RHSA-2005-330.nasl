#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:330 and 
# CentOS Errata and Security Advisory 2005:330 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21803);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-0468", "CVE-2005-0469");
  script_osvdb_id(15093, 15094);
  script_xref(name:"RHSA", value:"2005:330");

  script_name(english:"CentOS 3 : krb5 (CESA-2005:330)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated krb5 packages which fix two buffer overflow vulnerabilities in
the included Kerberos-aware telnet client are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Kerberos is a networked authentication system which uses a trusted
third party (a KDC) to authenticate clients and servers to each other.

The krb5-workstation package includes a Kerberos-aware telnet client.
Two buffer overflow flaws were discovered in the way the telnet client
handles messages from a server. An attacker may be able to execute
arbitrary code on a victim's machine if the victim can be tricked into
connecting to a malicious telnet server. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the names
CVE-2005-0468 and CVE-2005-0469 to these issues.

Users of krb5 should update to these erratum packages which contain a
backported patch to correct this issue.

Red Hat would like to thank iDEFENSE for their responsible disclosure
of this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-March/011507.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e97505f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-March/011512.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85776a03"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-March/011513.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e02941ec"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/28");
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
if (rpm_check(release:"CentOS-3", reference:"krb5-devel-1.2.7-42")) flag++;
if (rpm_check(release:"CentOS-3", reference:"krb5-libs-1.2.7-42")) flag++;
if (rpm_check(release:"CentOS-3", reference:"krb5-server-1.2.7-42")) flag++;
if (rpm_check(release:"CentOS-3", reference:"krb5-workstation-1.2.7-42")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
