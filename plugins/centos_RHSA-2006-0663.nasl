#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0663 and 
# CentOS Errata and Security Advisory 2006:0663 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22338);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-1168");
  script_bugtraq_id(19455);
  script_osvdb_id(27868);
  script_xref(name:"RHSA", value:"2006:0663");

  script_name(english:"CentOS 3 / 4 : ncompress (CESA-2006:0663)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ncompress packages that address a security issue and fix bugs
are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The ncompress package contains file compression and decompression
utilities, which are compatible with the original UNIX compress
utility (.Z file extensions).

Tavis Ormandy of the Google Security Team discovered a lack of bounds
checking in ncompress. An attacker could create a carefully crafted
file that could execute arbitrary code if uncompressed by a victim.
(CVE-2006-1168)

In addition, two bugs that affected Red Hat Enterprise Linux 4
ncompress packages were fixed :

* The display statistics and compression results in verbose mode were
not shown when operating on zero length files.

* An attempt to compress zero length files resulted in an unexpected
return code.

Users of ncompress are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013219.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4dcc7a1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013222.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9d82c97"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013234.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15fb3164"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013235.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72616e43"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013248.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f31c206d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013249.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33b6fe20"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ncompress package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ncompress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/10");
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
if (rpm_check(release:"CentOS-3", reference:"ncompress-4.2.4-39.rhel3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"ncompress-4.2.4-43.rhel4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
