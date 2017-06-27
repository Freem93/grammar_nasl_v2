#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-1008.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(20074);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:09:32 $");

  script_xref(name:"FEDORA", value:"2005-1008");

  script_name(english:"Fedora Core 3 : ethereal-0.10.13-1.FC3.1 (2005-1008)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ethereal 0.10.13 is scheduled to be released, which fixes the
following issues :

The ISAKMP dissector could exhaust system memory. (CVE-2005-3241)
Fixed in: r15163 Bug IDs: none Versions affected: 0.10.11 to 0.10.12.

The FC-FCS dissector could exhaust system memory.
(CVE-2005-3241) Fixed in: r15204 Bug IDs: 312 Versions
affected: 0.9.0 to 0.10.12.

The RSVP dissector could exhaust system memory.
(CVE-2005-3241) Fixed in: r15206, r15600 Bug IDs: 311, 314,
382 Versions affected: 0.9.4 to 0.10.12.

The ISIS LSP dissector could exhaust system memory.
(CVE-2005-3241) Fixed in: r15245 Bug IDs: 320, 326 Versions
affected: 0.8.18 to 0.10.12.

The IrDA dissector could crash. (CVE-2005-3242) Fixed in:
r15265, r15267 Bug IDs: 328, 329, 330, 334, 335, 336
Versions affected: 0.10.0 to 0.10.12.

The SLIMP3 dissector could overflow a buffer.
(CVE-2005-3243) Fixed in: r15279 Bug IDs: 327 Versions
affected: 0.9.1 to 0.10.12.

The BER dissector was susceptible to an infinite loop.
(CVE-2005-3244) Fixed in: r15292 Bug IDs: none Versions
affected: 0.10.3 to 0.10.12.

The SCSI dissector could dereference a NULL pointer and
crash. (CVE-2005-3246) Fixed in: r15289 Bug IDs: none
Versions affected: 0.10.3 to 0.10.12.

If the 'Dissect unknown RPC program numbers' option was
enabled, the ONC RPC dissector might be able to exhaust
system memory. This option is disabled by default.
(CVE-2005-3245) Fixed in: r15290 Bug IDs: none Versions
affected: 0.7.7 to 0.10.12.

The sFlow dissector could dereference a NULL pointer and
crash (CVE-2005-3246) Fixed in: r15375 Bug IDs: 356 Versions
affected: 0.9.14 to 0.10.12.

The RTnet dissector could dereference a NULL pointer and
crash (CVE-2005-3246) Fixed in: r15673 Bug IDs: none
Versions affected: 0.10.8 to 0.10.12.

The SigComp UDVM could go into an infinite loop or crash.
(CVE-2005-3247) Fixed in: r15715, r15901, r15919 Bug IDs:
none Versions affected: 0.10.12.

If SMB transaction payload reassembly is enabled the SMB
dissector could crash. This preference is disabled by
default. (CVE-2005-3242) Fixed in: r15789 Bug IDs: 421
Versions affected: 0.9.7 to 0.10.12.

The X11 dissector could attempt to divide by zero.
(CVE-2005-3248) Fixed in: r15927 Bug IDs: none Versions
affected: 0.10.1 to 0.10.12.

The AgentX dissector could overflow a buffer.
(CVE-2005-3243) Fixed in: r16003 Bug IDs: none Versions
affected: 0.10.10 to 0.10.12.

The WSP dissector could free an invalid pointer.
(CVE-2005-3249) Fixed in: r16220 Bug IDs: none Versions
affected: 0.10.1 to 0.10.12.

iDEFENSE found a buffer overflow in the SRVLOC dissector.
(CVE-2005-3184) Fixed in: r16206 Bug IDs: none Versions
affected: 0.10.0 to 0.10.12.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-October/001502.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e8ffd90"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected ethereal, ethereal-debuginfo and / or
ethereal-gnome packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ethereal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ethereal-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 3.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC3", reference:"ethereal-0.10.13-1.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"ethereal-debuginfo-0.10.13-1.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"ethereal-gnome-0.10.13-1.FC3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ethereal / ethereal-debuginfo / ethereal-gnome");
}
