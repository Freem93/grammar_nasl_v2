#%NASL_MIN_LEVEL 99999
# @DEPRECATED@
#
# This script has been deprecated as the associated patch is not
# currently a security fix.
#
# Disabled on 2012/09/06.
#

#
# (C) Tenable Network Security, Inc.
#
# This script was automatically generated from
# Mandriva Linux Security Advisory MDVA-2009:121.
#

if (!defined_func("bn_random")) exit(0);

include("compat.inc");

if (description)
{
  script_id(47936);
  script_version("$Revision: 1.6 $"); 
  script_cvs_date("$Date: 2012/10/04 19:39:07 $");

  script_name(english:"MDVA-2009:121 : pulseaudio");
  script_summary(english:"Checks for patch(es) in 'rpm -qa' output");

  script_set_attribute(attribute:"synopsis", value: 
"The remote Mandriva host is missing one or more security-related
patches.");
  script_set_attribute(attribute:"description", value:
"Multiple bugs has been identified and corrected in pulseaudio:

- alsa: allow configuration of fallback device strings in profiles
util: if NULL is passed to pa_path_get_filename() just hand it
through alsa: don't hit an assert when invalid module arguments are
passed - alsa: fix wording, we are speaking of card profiles, not
output profiles - alsa: initialize buffer size before number of
periods to improve compat with some backends - conf: remove obsolete
module-idle-time directive from default config file/man page - core:
make sure soft mute status stays in sync with hw mute status endian:
fix LE/BE order for 24 bit accessor functions - log: print file name
only when we have it - man: document 24bit sample types in man page -
man: document log related daemon.conf options - man: document that
tsched doesn't use fragment settings - mutex: when we fail to fill in
mutex into static mutex ptr free it again - oss: don't deadlock when
we try to resume an OSS device that lacks a mixer - simple-protocol:
don't hit an assert when we call connection_unlink() early - idxset:
add enumeration macro PA_IDXSET_FOREACH - rescue-streams: when one
stream move fails try to continue with the remaining ones - sample:
correctly pass s24-32 formats - sample-util: fix iteration loop when
adjusting volume of s24 samples - sample-util: properly allocate
silence block for s24-32 formats - sconv: fix a few minor conversion
issues - alsa: be a bit more verbose when a hwparam call fails -
rescue: make we don't end up in an endless loop when we can't move a
sink input - core: introduce pa_{sink,source}_set_fixed_latency() -
core: cache requested latency only when we are running, not while we
are still constructing - sample: fix build on BE archs - alsa:
properly convert return values of snd_strerror() to utf8 - alsa:
remove debug codeAdditional

In addition to these fixes, several patches were recommended by
upstream and QAed with help from Mandriva volunteers. These patches
are also included.");
  script_set_attribute(attribute:"see_also", value:"http://www.mandriva.com/security/advisories?name=MDVA-2009:121");
  script_set_attribute(attribute:"solution", value:"Update the affected package(s).");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/26");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux");
  script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/07/30");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");
 
  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch is not currently a security fix.");


include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Mandrake/release")) exit(0, "The host is not running Mandrake Linux.");
if (!get_kb_item("Host/Mandrake/rpm-list")) exit(1, "Could not get the list of packages.");

flag = 0;

if (rpm_check(reference:"libpulseaudio0-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libpulseaudio-devel-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libpulseglib20-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"libpulsezeroconf0-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-esound-compat-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-module-bluetooth-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-module-gconf-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-module-jack-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-module-lirc-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-module-x11-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-module-zeroconf-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-utils-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"i386", yank:"mdv")) flag++;

if (rpm_check(reference:"lib64pulseaudio0-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64pulseaudio-devel-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64pulseglib20-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"lib64pulsezeroconf0-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-esound-compat-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-module-bluetooth-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-module-gconf-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-module-jack-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-module-lirc-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-module-x11-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-module-zeroconf-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;
if (rpm_check(reference:"pulseaudio-utils-0.9.15-2.0.4mdv2009.1", release:"MDK2009.1", cpu:"x86_64", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else 
{
  exit(0, "The host is not affected.");
}
