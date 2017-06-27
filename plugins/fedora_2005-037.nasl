# @DEPRECATED@ 
# 
# This script has been deprecated by fedora_2006-037.nasl. 
# 
# Disabled on 2012/10/01. 
# 

#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from Fedora Security
# Advisory 2005-037.
#

include("compat.inc");

if (description)
{
  script_id(62252);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/10/01 13:51:08 $");

  script_cve_id("CVE-2005-3193");
  script_xref(name:"FEDORA", value:"2005-037");

  script_name(english:"Fedora Core 4 : kdegraphics-3.5.0-0.2.fc4 (2005-037)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several flaws were discovered in Xpdf. An attacker could construct a
carefully crafted PDF file that could cause xpdf to crash or possibly
execute arbitrary code when opened. The Common Vulnerabilities and
Exposures project assigned the name CVE-2005-3193 to these issues. 

Users of kdegraphics should upgrade to this updated package, which
contains a patch to resolve these issues."
  );
  # http://lists.fedoraproject.org/pipermail/announce/2006-January/001748.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d41eb7a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected kdegraphics, kdegraphics-debuginfo and / or
kdegraphics-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/16");
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
exit(0, "This plugin has been deprecated. Refer to plugin #20730 (fedora_2006-037.nasl) instead.");

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
if (rpm_check(release:"FC4", reference:"kdegraphics-3.5.0-0.2.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"kdegraphics-debuginfo-3.5.0-0.2.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"kdegraphics-devel-3.5.0-0.2.fc4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
