#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:078. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(18171);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/31 23:51:57 $");

  script_cve_id("CVE-2005-0194", "CVE-2005-0626", "CVE-2005-0718", "CVE-2005-1345");
  script_xref(name:"MDKSA", value:"2005:078");

  script_name(english:"Mandrake Linux Security Advisory : squid (MDKSA-2005:078)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandrake Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Squid 2.5, when processing the configuration file, parses empty Access
Control Lists (ACLs), including proxy_auth ACLs without defined auth
schemes, in a way that effectively removes arguments, which could
allow remote attackers to bypass intended ACLs if the administrator
ignores the parser warnings. (CVE-2005-0194)

Race condition in Squid 2.5.STABLE7 to 2.5.STABLE9, when using the
Netscape Set-Cookie recommendations for handling cookies in caches,
may cause Set-Cookie headers to be sent to other users, which allows
attackers to steal the related cookies. (CVE-2005-0626)

Squid 2.5.STABLE7 and earlier allows remote attackers to cause a
denial of service (segmentation fault) by aborting the connection
during a (1) PUT or (2) POST request, which causes Squid to access
previosuly freed memory. (CVE-2005-0718)

A bug in the way Squid processes errors in the access control list was
also found. It is possible that an error in the access control list
could give users more access than intended. (CVE-2005-1345)

In addition, due to subtle bugs in the previous backported updates of
squid (Bugzilla #14209), all the squid-2.5 versions have been updated
to squid-2.5.STABLE9 with all the STABLE9 patches from the squid
developers.

The updated packages are patched to fix these problems."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected squid package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK10.0", reference:"squid-2.5.STABLE9-1.1.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", cpu:"i386", reference:"squid-2.5.STABLE6-2.4.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"squid-2.5.STABLE9-1.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
