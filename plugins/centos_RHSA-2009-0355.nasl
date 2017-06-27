#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0355 and 
# CentOS Errata and Security Advisory 2009:0355 respectively.
#

include("compat.inc");

if (description)
{
  script_id(38894);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2009-0547", "CVE-2009-0582", "CVE-2009-0587");
  script_bugtraq_id(33720, 34100, 34109);
  script_osvdb_id(52673, 52701, 52702, 52703);
  script_xref(name:"RHSA", value:"2009:0355");

  script_name(english:"CentOS 4 : evolution / evolution-data-server (CESA-2009:0355)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evolution and evolution-data-server packages that fixes
multiple security issues are now available for Red Hat Enterprise
Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Evolution is the integrated collection of e-mail, calendaring, contact
management, communications, and personal information management (PIM)
tools for the GNOME desktop environment.

Evolution Data Server provides a unified back-end for applications
which interact with contacts, task and calendar information. Evolution
Data Server was originally developed as a back-end for Evolution, but
is now used by multiple other applications.

Evolution did not properly check the Secure/Multipurpose Internet Mail
Extensions (S/MIME) signatures used for public key encryption and
signing of e-mail messages. An attacker could use this flaw to spoof a
signature by modifying the text of the e-mail message displayed to the
user. (CVE-2009-0547)

It was discovered that evolution did not properly validate NTLM (NT
LAN Manager) authentication challenge packets. A malicious server
using NTLM authentication could cause evolution to disclose portions
of its memory or crash during user authentication. (CVE-2009-0582)

Multiple integer overflow flaws which could cause heap-based buffer
overflows were found in the Base64 encoding routines used by evolution
and evolution-data-server. This could cause evolution, or an
application using evolution-data-server, to crash, or, possibly,
execute an arbitrary code when large untrusted data blocks were
Base64-encoded. (CVE-2009-0587)

All users of evolution and evolution-data-server are advised to
upgrade to these updated packages, which contain backported patches to
correct these issues. All running instances of evolution and
evolution-data-server must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015680.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f17d74a7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015902.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015903.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution and / or evolution-data-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 189, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"evolution-2.0.2-41.el4_7.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"evolution-data-server-1.0.2-14.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"evolution-data-server-devel-1.0.2-14.el4_7.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"evolution-devel-2.0.2-41.el4_7.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
