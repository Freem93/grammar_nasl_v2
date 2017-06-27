#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-1383.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(27713);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 21:54:54 $");

  script_xref(name:"FEDORA", value:"2007-1383");

  script_name(english:"Fedora 7 : xpdf-3.02-1.fc7 (2007-1383)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Changes since 3.01: Added anti-aliasing for vector graphics; added the
vectorAntialias xpdfrc option; added the '-aaVector' switch to xpdf
and pdftoppm. Implemented stroke adjustment (always enabled by
default, ignoring the SA parameter, to match Adobe's behavior), and
added the strokeAdjust xpdfrc command. Support PDF 1.6 and PDF 1.7.
Added support for AES decryption. Added support for OpenType fonts
(only tested with 8-bit CFF data so far). Added user-configurable
key/mouse bindings - the bind/unbind xpdfrc commands. Cleaned up the
full-screen mode code and added the ability to toggle it on the fly
(the default key binding is alt-f). Pdfimages with the -j option now
writes JPEG files for 1-component (grayscale) DCT images, in addition
to 3-component (RGB) images. Fixed bugs in handling sampled (type 0)
functions with 32-bit samples. Fixed some things to support DeviceN
color spaces with up to 32 colorants. Pdftops now constructs the
%%Creator and %%Title DSC comments from the relevant information in
the PDF Info dictionary. Tweak the TrueType font encoding deciphering
algorithm. Added the 'mapUnkownCharNames' xpdfrc option. Fix a bug
(that only showed up with certain window managers) in the intermediate
resize event optimization. [Thanks to Michael Rogers.] Check for a
broken/missing embedded font (this was causing xpdf to crash). Added
support for transfer functions in PostScript output. Be a bit more
tolerant of Link destinations that contain null values for positioning
parameters. Use ordered dot dithering instead of clustered dot
dithering at resolutions below 300 dpi (for monochrome output). Fixed
security holes (bounds checking issues) in several places. Don't
bother creating a SplashFont (allocating memory) for fonts that are
only used for hidden text - this avoids problems with fonts of
unreasonably large sizes. Clipping in TextOutputDev was off for
characters on the left edge of the page. The scn and SCN operators
weren't correctly handling colors with more than four components.
FoFiType1::writeEncoded wasn't always correctly finding the end of the
encoding. Use the ColorTransform parameter in the DCTDecode stream
dictionary. Type 3 fonts are allowed to have a bbox of [0 0 0 0],
which means 'unspecified' -- don't issue error messages in that case.
Perform the transform (to device space) in Splash instead of in
SplashOutputDev -- this is needed to correctly handle round joins and
caps on stroked paths. PSOutputDev now rasterizes any pages that use
transparency. Limit the crop, bleed, trim, and art boxes to the edges
of the media box (per the PDF spec). Change GString to increase the
allocation increment by powers of two. Handle whitespace in hex
strings in CMap files/streams. Use strings instead of names for
separation colorant names in PSOutputDev. For explicitly masked images
where the mask is higher resolution than the image, use the soft mask
code. Avoid problems with very large x-steps in the PostScript output
for tiling pattern fills. Avoid a divide-by-zero in stitching
functions which have a subfunction with empty bounds. Honor the
'Hidden', 'NoView', and 'Print' flags on annotations. Rewrote the
pixel rendering code in Splash to use a single set of pixel pipeline
functions. Added support for transparency groups and soft masks. Fixed
the transparency blend functions to match the addendum published by
Adobe. Changed Splash/SplashBitmap to store alpha in a separate plane.
Setting the color space now selects the correct default color for that
color space. Remove the mutex lock from GlobalParams::getErrQuiet() to
avoid a deadlock when parseCIDToUnicode() or parseUnicodeToUnicode()
calls it from inside a locked section. Added error checking (on the
argument count) in the sc/SC/scn/SCN operators. Skip over notdef
glyphs in TrueType fonts (which sometimes get drawn as little boxes),
to match Adobe's behavior. Painting operations in a Separation color
space with the 'None' colorant or a DeviceN color space with all
colorants set to 'None' never mark the page. Fixed an obscure bug in
the JPX decoder - it wasn't reading the extra stuffing byte in the
case where the last byte of a packet header was 0xff. Change the
TrueType font parser (FoFiTrueType) to change the glyph count rather
than report an error if the 'loca' table is too small. Fixed a couple
of bugs in the JBIG2 decoder. Added stochastic clustered dot
dithering. Added the screenType, screenSize, screenDotRadius,
screenGamma, screenBlackThreshold, and screenWhiteThreshold xpdfrc
settings. PSOutputDev now correctly handles invalid Type 3 charprocs
which don't start with a d0 or d1 operator. FreeType 2.2.x support -
get rid of the FT_INTERNAL_OBJECTS_H include, and add some 'const'
declarations. Handle PDFDocEncoding in Info dictionary strings. Tweak
the xref repair code - ignore whitespace at the start of lines when
looking for objects. Added the '-exec' switch to xpdf. Removed the
xpdf.viKeys X resource. Changed the color key / explicit masked image
code in PSOutputDev to generate better PS code, including a Level 3
option. Tweaked the DEBUG_MEM code for performance. Move the JBIG2
global stream reading code into reset() instead of the constructor -
this way, pdftotext doesn't end up reading the global stream. Added
the '-preload' option to pdftops and the psPreload xpdfrc command.
Added the 'zoom to selection' command (on the popup menu). Fix a bug
(in xpdf/pdftoppm/pdftops) with tiling patterns whose bbox size is
different from their xStep/yStep. Implemented stroke with pattern
color spaces. Following a link to a page whose CropBox was different
from the MediaBox was resulting in an incorrect scroll position. Parse
truncated date strings from the Info dictionary correctly. Change
FoFiType1 to handle Type 1 fonts with two /Encoding keys. Extend the
PSOutputDev shaded fill code to handle DeviceCMYK shaded fills in
level2sep and level3sep modes. Detect infinite loops in the Page tree.
Optimized the ASCII85Encoder code. Tweaked the text extractor to do a
better job of lining up rows of text. Leave images compressed (or
re-compress them with RLE) in PostScript output when setting up images
for forms and Type 3 fonts (or with -preload). Extend FoFiType1 to
handle Type 1 fonts with octal character codes in their encodings. Use
a custom string formatter to avoid problems with locale-based decimal
formatting (commas instead of periods) in PS output. Allow comments in
PostScript-type functions. Change the TrueType font parser
(FoFiTrueType) to delete glyf table entries that are too short.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-August/003053.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e822c961"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xpdf and / or xpdf-debuginfo packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xpdf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"xpdf-3.02-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"xpdf-debuginfo-3.02-1.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xpdf / xpdf-debuginfo");
}
