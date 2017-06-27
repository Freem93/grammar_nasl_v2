#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0386 and 
# CentOS Errata and Security Advisory 2007:0386 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(25403);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2006-5297", "CVE-2007-1558", "CVE-2007-2683");
  script_bugtraq_id(23257);
  script_osvdb_id(30094, 34856, 34973);
  script_xref(name:"RHSA", value:"2007:0386");

  script_name(english:"CentOS 3 / 4 / 5 : mutt (CESA-2007:0386)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated mutt package that fixes several security bugs is now
available for Red Hat Enterprise Linux 3, 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Mutt is a text-mode mail user agent.

A flaw was found in the way Mutt used temporary files on NFS file
systems. Due to an implementation issue in the NFS protocol, Mutt was
not able to exclusively open a new file. A local attacker could
conduct a time-dependent attack and possibly gain access to e-mail
attachments opened by a victim. (CVE-2006-5297)

A flaw was found in the way Mutt processed certain APOP authentication
requests. By sending certain responses when mutt attempted to
authenticate against an APOP server, a remote attacker could
potentially acquire certain portions of a user's authentication
credentials. (CVE-2007-1558)

A flaw was found in the way Mutt handled certain characters in gecos
fields which could lead to a buffer overflow. The gecos field is an
entry in the password database typically used to record general
information about the user. A local attacker could give themselves a
carefully crafted 'Real Name' which could execute arbitrary code if a
victim uses Mutt and expands the attackers alias. (CVE-2007-2683)

All users of mutt should upgrade to this updated package, which
contains a backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013868.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71f0ffe5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013869.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33de5b44"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013870.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d434799f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013871.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb5106ec"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013872.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8141792"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013873.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?578b9938"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013874.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d92a35d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013875.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7be8530"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected mutt package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mutt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"mutt-1.4.1-5.el3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"mutt-1.4.1-12.0.3.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"mutt-1.4.2.2-3.0.2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
