#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0746 and 
# CentOS Errata and Security Advisory 2006:0746 respectively.
#

include("compat.inc");

if (description)
{
  script_id(23788);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/04/28 18:05:36 $");

  script_cve_id("CVE-2006-5989");
  script_osvdb_id(30548);
  script_xref(name:"RHSA", value:"2006:0746");

  script_name(english:"CentOS 4 : mod_auth_kerb (CESA-2006:0746)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mod_auth_kerb packages that fix a security flaw and a bug in
multiple realm handling are now available for Red Hat Enterprise Linux
4.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

mod_auth_kerb is module for the Apache HTTP Server designed to provide
Kerberos authentication over HTTP.

An off by one flaw was found in the way mod_auth_kerb handles certain
Kerberos authentication messages. A remote client could send a
specially crafted authentication request which could crash an httpd
child process (CVE-2006-5989).

A bug in the handling of multiple realms configured using the
'KrbAuthRealms' directive has also been fixed.

All users of mod_auth_kerb should upgrade to these updated packages,
which contain backported patches that resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-December/013422.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?510bcc5c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-December/013427.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?278ace58"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-December/013428.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2da17a7d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mod_auth_kerb package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_auth_kerb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"mod_auth_kerb-5.0-1.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"mod_auth_kerb-5.0-1.3.c4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"mod_auth_kerb-5.0-1.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
