#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2008:009. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(37526);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/06/01 00:01:21 $");

  script_cve_id("CVE-2007-5964", "CVE-2007-6285");
  script_xref(name:"MDVSA", value:"2008:009-1");

  script_name(english:"Mandriva Linux Security Advisory : autofs (MDVSA-2008:009-1)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Mandriva Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The default behaviour of autofs 5 for the hosts map did not specify
the nosuid and nodev mount options. This could allow a local user with
control of a remote NFS server to create a setuid root executable on
the exported filesystem of the remote NFS server. If this filesystem
was mounted with the default hosts map, it would allow the user to
obtain root privileges (CVE-2007-5964). Likewise, the same scenario
would be available for local users able to create device files on the
exported filesystem which could allow the user to gain access to
important system devices (CVE-2007-6285).

Because the default behaviour of autofs was to mount -hosts map
entries with the dev and suid options enabled by default, autofs has
been altered to always use nodev and nosuid by default. In order to
have the old behaviour, the configuration must now explicitly set the
dev and/or suid options.

This change only affects the -hosts map which corresponds to the /net
entry in the default configuration.

Update :

The previous update shipped with an incorrect LDAP lookup module that
would prevent the automount daemon from starting. This update corrects
that problem."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected autofs package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:autofs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2007.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2008.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2007.1", reference:"autofs-5.0.2-8.4mdv2007.1", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2008.0", reference:"autofs-5.0.2-8.4mdv2008.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
