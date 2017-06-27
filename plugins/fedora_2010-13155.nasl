#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-13155.
#

include("compat.inc");

if (description)
{
  script_id(49106);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/11 13:16:08 $");

  script_cve_id("CVE-2010-2947");
  script_bugtraq_id(42592);
  script_osvdb_id(67370);
  script_xref(name:"FEDORA", value:"2010-13155");

  script_name(english:"Fedora 12 : libHX-3.6-1.fc12 / pam_mount-2.5-1.fc12 (2010-13155)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to libHX 3.6 fixing a buffer overflow in HX_split(): *
http://libhx.gi
t.sourceforge.net/git/gitweb.cgi?p=libhx/libhx;a=commitdiff;h=904a46f9
0d pam_mount v2.5 (August 10 2010) ===============================
Changes: - mount.crypt: fix incorrect processing of binary files in
keyfile passthrough - call mount.crypt by means of mount -t crypt
(selinux), same for umount - reorder the default path to search in
/usr/local first, then /usr, / - config: add missing fd0ssh command to
restore volumes using ssh - ofl is now run as a separate process
(selinux policy simplification) libHX v3.6 (August 16 2010)
=========================== Fixed: - bitmap: set/clear/test had no
effect due to wrong type selection - bitmap: avoid left-shift larger
than type on 64-bit

  - string: fixed buffer overflow in HX_split when too few
    fields were present in the input libHX 3.5 (August 01
    2010) ========================== Fixed: - format2:
    failure to skip escaped char in '%(echo foo\ bar)' was
    corrected - proc: properly check for
    HXPROC_STDx--HXPROC_STDx_NULL overlap - strquote: do not
    cause allocation with invalid format numbers
    Enhancements: - format2: add the %(exec) function -
    format2: add the %(shell) function - format2: security
    feature for %(exec) and %(shell) - format2: add the
    %(snl) function - string: HX_strquote gained
    HXQUOTE_LDAPFLT (LDAP search filter) support - string:
    HX_strquote gained HXQUOTE_LDAPRDN (LDAP relative DN)
    support Changes: - format1: removed older formatter in
    favor of format2 - format2: add check for empty key -
    format2: function-specific delimiters - format2: do
    nest-counting even with normal parentheses - format2:
    check for zero-argument function calls

  - hashmap: do not needlessy change TID when no reshape was
    done - string: HX_basename (the fast variant) now
    recognizes the root directory - string: HX_basename now
    returns the trailing component with slashes instead of
    everything after the last slash (which may have been
    nothing)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://libhx.gi"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=625866"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-September/046980.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b78dd5e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-September/046981.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?326ae779"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libHX and / or pam_mount packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libHX");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pam_mount");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"libHX-3.6-1.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"pam_mount-2.5-1.fc12")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libHX / pam_mount");
}
