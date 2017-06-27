#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1128 and 
# CentOS Errata and Security Advisory 2007:1128 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43663);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/05/19 23:34:18 $");

  script_cve_id("CVE-2007-5964");
  script_bugtraq_id(26841);
  script_osvdb_id(40441);
  script_xref(name:"RHSA", value:"2007:1128");

  script_name(english:"CentOS 5 : autofs (CESA-2007:1128)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated autofs packages are now available to fix a security flaw for
Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The autofs utility controls the operation of the automount daemon,
which automatically mounts and unmounts file systems after a period of
inactivity.

There was a security issue with the default installed configuration of
autofs version 5 whereby the entry for the 'hosts' map did not specify
the 'nosuid' mount option. A local user with control of a remote nfs
server could create a setuid root executable within an exported
filesystem on the remote nfs server that, if mounted using the default
hosts map, would allow the user to gain root privileges.
(CVE-2007-5964)

Due to the fact that autofs always mounted hosts map entries suid by
default, autofs has now been altered to always use the 'nosuid' option
when mounting from the default hosts map. The 'suid' option must be
explicitly given in the master map entry to revert to the old
behavior. This change affects only the hosts map which corresponds to
the /net entry in the default configuration.

Users are advised to upgrade to these updated autofs packages, which
resolve this issue.

Red Hat would like to thank Josh Lange for reporting this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014507.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38a1ad08"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014508.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c4f981b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected autofs package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autofs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"autofs-5.0.1-0.rc2.55.el5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
