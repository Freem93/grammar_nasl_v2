#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:357 and 
# CentOS Errata and Security Advisory 2005:357 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21810);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-0758", "CVE-2005-0988", "CVE-2005-1228");
  script_osvdb_id(15487, 15721, 16371);
  script_xref(name:"RHSA", value:"2005:357");

  script_name(english:"CentOS 3 / 4 : gzip (CESA-2005:357)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gzip package is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The gzip package contains the GNU gzip data compression program.

A bug was found in the way zgrep processes file names. If a user can
be tricked into running zgrep on a file with a carefully crafted file
name, arbitrary commands could be executed as the user running zgrep.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0758 to this issue.

A bug was found in the way gunzip modifies permissions of files being
decompressed. A local attacker with write permissions in the directory
in which a victim is decompressing a file could remove the file being
written and replace it with a hard link to a different file owned by
the victim. gunzip then gives the linked file the permissions of the
uncompressed file. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0988 to this issue.

A directory traversal bug was found in the way gunzip processes the -N
flag. If a victim decompresses a file with the -N flag, gunzip fails
to sanitize the path which could result in a file owned by the victim
being overwritten. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1228 to this issue.

Users of gzip should upgrade to this updated package, which contains
backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011823.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?19f0c672"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011824.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24662e6f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011825.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?097e1e68"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011826.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4e85999"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011835.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf675f81"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011841.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61d14aeb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gzip package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gzip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/04");
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
if (rpm_check(release:"CentOS-3", reference:"gzip-1.3.3-12.rhel3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gzip-1.3.3-15.rhel4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
