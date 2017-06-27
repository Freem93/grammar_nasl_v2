# @DEPRECATED@
#
# This script has been deprecated by fedora_2004-173.nasl.
#
# Disabled on 2012/10/01.
#

#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from Fedora Security
# Advisory 2004-185.
#

include("compat.inc");

if (description)
{
  script_id(62244);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/10/01 13:51:08 $");

  script_xref(name:"FEDORA", value:"2004-185");

  script_name(english:"Fedora Core 1 : libpng-1.2.5-4 (2004-185)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"During an audit of Red Hat Linux updates, the Fedora Legacy team found
a security issue in libpng that had not been fixed in Fedora Core. An
attacker could carefully craft a PNG file in such a way that it would
cause an application linked to libpng to crash or potentially execute
arbitrary code when opened by a victim."
  );
  # http://lists.fedoraproject.org/pipermail/announce/2004-June/000175.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a971e3f9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libpng, libpng-debuginfo and / or libpng-devel
packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #13727 (fedora_2004-173.nasl) instead.");

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC1", cpu:"x86_64", reference:"libpng-1.2.5-4")) flag++;
if (rpm_check(release:"FC1", reference:"libpng-debuginfo-1.2.5-4")) flag++;
if (rpm_check(release:"FC1", reference:"libpng-devel-1.2.5-4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
