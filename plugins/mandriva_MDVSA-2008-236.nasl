#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:236. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(36821);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/28 21:39:22 $");

  script_cve_id("CVE-2007-2953", "CVE-2008-2712", "CVE-2008-2953", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-3076", "CVE-2008-4101", "CVE-2008-4677");
  script_bugtraq_id(25095);
  script_xref(name:"MDVSA", value:"2008:236-1");

  script_name(english:"Mandriva Linux Security Advisory : vim (MDVSA-2008:236-1)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were found in the vim editor :

A number of input sanitization flaws were found in various vim system
functions. If a user were to open a specially crafted file, it would
be possible to execute arbitrary code as the user running vim
(CVE-2008-2712).

Ulf H&Atilde;&curren;rnhammar of Secunia Research found a format
string flaw in vim's help tags processor. If a user were tricked into
executing the helptags command on malicious data, it could result in
the execution of arbitrary code as the user running vim
(CVE-2008-2953).

A flaw was found in how tar.vim handled TAR archive browsing. If a
user were to open a special TAR archive using the plugin, it could
result in the execution of arbitrary code as the user running vim
(CVE-2008-3074).

A flaw was found in how zip.vim handled ZIP archive browsing. If a
user were to open a special ZIP archive using the plugin, it could
result in the execution of arbitrary code as the user running vim
(CVE-2008-3075).

A number of security flaws were found in netrw.vim, the vim plugin
that provides the ability to read and write files over the network. If
a user opened a specially crafted file or directory with the netrw
plugin, it could result in the execution of arbitrary code as the user
running vim (CVE-2008-3076).

A number of input validation flaws were found in vim's keyword and tag
handling. If vim looked up a document's maliciously crafted tag or
keyword, it was possible to execute arbitary code as the user running
vim (CVE-2008-4101).

A vulnerability was found in certain versions of netrw.vim where it
would send FTP credentials stored for an FTP session to subsequent FTP
sessions to servers on different hosts, exposing FTP credentials to
remote hosts (CVE-2008-4677).

This update provides vim 7.2 (patchlevel 65) which corrects all of
these issues and introduces a number of new features and bug fixes.

Update :

The previous vim update incorrectly introduced a requirement on
libruby and also conflicted with a file from the git-core package (in
contribs). These issues have been corrected with these updated
packages."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 78, 94, 255);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vim-X11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vim-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vim-enhanced");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:vim-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK2008.0", reference:"vim-X11-7.2.065-9.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"vim-common-7.2.065-9.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"vim-enhanced-7.2.065-9.3mdv2008.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.0", reference:"vim-minimal-7.2.065-9.3mdv2008.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.1", reference:"vim-X11-7.2.065-9.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"vim-common-7.2.065-9.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"vim-enhanced-7.2.065-9.3mdv2008.1", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2008.1", reference:"vim-minimal-7.2.065-9.3mdv2008.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2009.0", reference:"vim-X11-7.2.065-9.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vim-common-7.2.065-9.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vim-enhanced-7.2.065-9.3mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"vim-minimal-7.2.065-9.3mdv2009.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
