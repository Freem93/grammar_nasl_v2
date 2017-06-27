#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0580 and 
# CentOS Errata and Security Advisory 2008:0580 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43697);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2007-2953", "CVE-2008-2712", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076", "CVE-2008-4101", "CVE-2008-6235");
  script_bugtraq_id(25095);
  script_osvdb_id(38674, 46306, 51437, 52164);
  script_xref(name:"RHSA", value:"2008:0580");

  script_name(english:"CentOS 5 : vim (CESA-2008:0580)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated vim packages that fix security issues are now available for
Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Vim (Visual editor IMproved) is an updated and improved version of the
vi editor.

Several input sanitization flaws were found in Vim's keyword and tag
handling. If Vim looked up a document's maliciously crafted tag or
keyword, it was possible to execute arbitrary code as the user running
Vim. (CVE-2008-4101)

Multiple security flaws were found in netrw.vim, the Vim plug-in
providing file reading and writing over the network. If a user opened
a specially crafted file or directory with the netrw plug-in, it could
result in arbitrary code execution as the user running Vim.
(CVE-2008-3076)

A security flaw was found in zip.vim, the Vim plug-in that handles ZIP
archive browsing. If a user opened a ZIP archive using the zip.vim
plug-in, it could result in arbitrary code execution as the user
running Vim. (CVE-2008-3075)

A security flaw was found in tar.vim, the Vim plug-in which handles
TAR archive browsing. If a user opened a TAR archive using the tar.vim
plug-in, it could result in arbitrary code execution as the user
runnin Vim. (CVE-2008-3074)

Several input sanitization flaws were found in various Vim system
functions. If a user opened a specially crafted file, it was possible
to execute arbitrary code as the user running Vim. (CVE-2008-2712)

Ulf Harnhammar, of Secunia Research, discovered a format string flaw
in Vim's help tag processor. If a user was tricked into executing the
'helptags' command on malicious data, arbitrary code could be executed
with the permissions of the user running Vim. (CVE-2007-2953)

All Vim users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015453.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5bff4d93"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-November/015454.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0357fe62"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected vim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 78, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"vim-X11-7.0.109-4.el5_2.4z")) flag++;
if (rpm_check(release:"CentOS-5", reference:"vim-common-7.0.109-4.el5_2.4z")) flag++;
if (rpm_check(release:"CentOS-5", reference:"vim-enhanced-7.0.109-4.el5_2.4z")) flag++;
if (rpm_check(release:"CentOS-5", reference:"vim-minimal-7.0.109-4.el5_2.4z")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
