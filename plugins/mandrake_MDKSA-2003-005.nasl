#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2003:005. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(13990);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/31 23:47:33 $");

  script_cve_id("CVE-2002-1661");
  script_xref(name:"MDKSA", value:"2003:005");

  script_name(english:"Mandrake Linux Security Advisory : leafnode (MDKSA-2003:005)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability was discovered by Jan Knutar in leafnode that Mark
Brown pointed out could be used in a Denial of Service attack. This
vulnerability causes leafnode to go into an infinite loop with 100%
CPU use when an article that has been crossposed to several groups,
one of which is the prefix of another, is requested by it's
Message-ID.

This vulnerability was introduced in 1.9.20 and fixed upstream in
version 1.9.30. Only Mandrake Linux 9.0 is affected by this, but
version 1.9.19 (which shipped with Mandrake Linux 8.2) is receiving an
update due to critical bugs in it that can corrupt parts of its news
spool under certain circumstances."
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=104127108823436&w=2
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=104127108823436&w=2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected leafnode package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:leafnode");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:9.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK8.2", cpu:"i386", reference:"leafnode-1.9.31-1.1mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK9.0", cpu:"i386", reference:"leafnode-1.9.31-1.1mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
