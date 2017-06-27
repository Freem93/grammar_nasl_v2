#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29911);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2012/05/17 10:53:20 $");

  script_name(english:"SuSE 10 Security Update : Intel i810 chips (ZYPP Patch Number 4728)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The drm i915 component in the kernel before 2.6.22.2, when used with
i965G and later chips ets, allows local users with access to an X11
session and Direct Rendering Manager (DRM) t o write to arbitrary
memory locations and gain privileges via a crafted batchbuffer.

This update also provides the latests i810 driver stack, which
includes fixes for FnFx handling (enables switching from internal to
external and internal monitor on Laptops)"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 4728.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2012 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:1, reference:"915resolution-0.5.2.1-1.2.5")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"intel-i810-Mesa-6.4.2.2-1.2.6")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"intel-i810-xorg-x11-6.9.0.2-2.2.12")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"sax2-7.1-125.41.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"sax2-gui-1.7-125.41.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"sax2-ident-1.7-125.42.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"sax2-libsax-7.1-125.41.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"sax2-libsax-csharp-7.1-121.41.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"sax2-libsax-perl-7.1-125.41.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, reference:"sax2-tools-2.7-125.41.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"intel-i810-agpgart-kmp-bigsmp-1.2_2.6.16.54_0.2.3-1.2.4")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"intel-i810-agpgart-kmp-default-1.2_2.6.16.54_0.2.3-1.2.4")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"intel-i810-agpgart-kmp-smp-1.2_2.6.16.54_0.2.3-1.2.4")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"intel-i810-agpgart-kmp-xen-1.2_2.6.16.54_0.2.3-1.2.4")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"intel-i810-agpgart-kmp-xenpae-1.2_2.6.16.54_0.2.3-1.2.4")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"intel-i810-drm-kmp-bigsmp-1.2_2.6.16.54_0.2.3-1.2.6")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"intel-i810-drm-kmp-default-1.2_2.6.16.54_0.2.3-1.2.6")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"intel-i810-drm-kmp-smp-1.2_2.6.16.54_0.2.3-1.2.6")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"intel-i810-drm-kmp-xen-1.2_2.6.16.54_0.2.3-1.2.6")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"intel-i810-drm-kmp-xenpae-1.2_2.6.16.54_0.2.3-1.2.6")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"intel-i810-agpgart-kmp-default-1.2_2.6.16.54_0.2.3-1.2.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"intel-i810-agpgart-kmp-smp-1.2_2.6.16.54_0.2.3-1.2.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"intel-i810-agpgart-kmp-xen-1.2_2.6.16.54_0.2.3-1.2.3")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"intel-i810-drm-kmp-default-1.2_2.6.16.54_0.2.3-1.2.5")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"intel-i810-drm-kmp-smp-1.2_2.6.16.54_0.2.3-1.2.5")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"x86_64", reference:"intel-i810-drm-kmp-xen-1.2_2.6.16.54_0.2.3-1.2.5")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"915resolution-0.5.2.1-1.2.5")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"intel-i810-Mesa-6.4.2.2-1.2.6")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"intel-i810-xorg-x11-6.9.0.2-2.2.12")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"sax2-7.1-125.41.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"sax2-gui-1.7-125.41.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"sax2-ident-1.7-125.42.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"sax2-libsax-7.1-125.41.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"sax2-libsax-devel-7.1-125.41.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"sax2-libsax-java-7.1-125.41.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"sax2-libsax-perl-7.1-125.41.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"sax2-libsax-python-7.1-125.41.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, reference:"sax2-tools-2.7-125.41.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"intel-i810-agpgart-kmp-bigsmp-1.2_2.6.16.54_0.2.3-1.2.4")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"intel-i810-agpgart-kmp-debug-1.2_2.6.16.54_0.2.3-1.2.4")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"intel-i810-agpgart-kmp-default-1.2_2.6.16.54_0.2.3-1.2.4")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"intel-i810-agpgart-kmp-smp-1.2_2.6.16.54_0.2.3-1.2.4")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"intel-i810-agpgart-kmp-xen-1.2_2.6.16.54_0.2.3-1.2.4")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"intel-i810-agpgart-kmp-xenpae-1.2_2.6.16.54_0.2.3-1.2.4")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"intel-i810-drm-kmp-bigsmp-1.2_2.6.16.54_0.2.3-1.2.6")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"intel-i810-drm-kmp-debug-1.2_2.6.16.54_0.2.3-1.2.6")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"intel-i810-drm-kmp-default-1.2_2.6.16.54_0.2.3-1.2.6")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"intel-i810-drm-kmp-smp-1.2_2.6.16.54_0.2.3-1.2.6")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"intel-i810-drm-kmp-xen-1.2_2.6.16.54_0.2.3-1.2.6")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"intel-i810-drm-kmp-xenpae-1.2_2.6.16.54_0.2.3-1.2.6")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"intel-i810-agpgart-kmp-debug-1.2_2.6.16.54_0.2.3-1.2.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"intel-i810-agpgart-kmp-default-1.2_2.6.16.54_0.2.3-1.2.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"intel-i810-agpgart-kmp-smp-1.2_2.6.16.54_0.2.3-1.2.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"intel-i810-agpgart-kmp-xen-1.2_2.6.16.54_0.2.3-1.2.3")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"intel-i810-drm-kmp-debug-1.2_2.6.16.54_0.2.3-1.2.5")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"intel-i810-drm-kmp-default-1.2_2.6.16.54_0.2.3-1.2.5")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"intel-i810-drm-kmp-smp-1.2_2.6.16.54_0.2.3-1.2.5")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"x86_64", reference:"intel-i810-drm-kmp-xen-1.2_2.6.16.54_0.2.3-1.2.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
