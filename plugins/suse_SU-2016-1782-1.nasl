#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1782-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93178);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2014-9805", "CVE-2014-9806", "CVE-2014-9807", "CVE-2014-9808", "CVE-2014-9809", "CVE-2014-9810", "CVE-2014-9811", "CVE-2014-9812", "CVE-2014-9813", "CVE-2014-9814", "CVE-2014-9815", "CVE-2014-9816", "CVE-2014-9817", "CVE-2014-9818", "CVE-2014-9819", "CVE-2014-9820", "CVE-2014-9822", "CVE-2014-9823", "CVE-2014-9824", "CVE-2014-9826", "CVE-2014-9828", "CVE-2014-9829", "CVE-2014-9830", "CVE-2014-9831", "CVE-2014-9834", "CVE-2014-9835", "CVE-2014-9836", "CVE-2014-9837", "CVE-2014-9838", "CVE-2014-9839", "CVE-2014-9840", "CVE-2014-9842", "CVE-2014-9844", "CVE-2014-9845", "CVE-2014-9846", "CVE-2014-9847", "CVE-2014-9849", "CVE-2014-9851", "CVE-2014-9853", "CVE-2014-9854", "CVE-2015-8894", "CVE-2015-8896", "CVE-2015-8897", "CVE-2015-8898", "CVE-2015-8901", "CVE-2015-8902", "CVE-2015-8903", "CVE-2016-4562", "CVE-2016-4563", "CVE-2016-4564", "CVE-2016-5687", "CVE-2016-5688", "CVE-2016-5689", "CVE-2016-5690", "CVE-2016-5691", "CVE-2016-5841", "CVE-2016-5842");
  script_osvdb_id(116360, 116361, 116362, 116363, 116367, 116370, 116372, 116374, 116377, 116380, 116383, 116384, 116385, 116387, 116389, 116390, 116391, 116393, 116394, 116396, 116397, 116398, 116399, 116400, 116401, 116402, 116403, 116404, 116405, 116407, 116408, 116409, 116410, 116411, 116412, 116413, 116414, 116416, 116417, 116418, 116419, 118660, 118661, 118662, 127960, 128604, 129831, 138399, 139334, 139335, 139336, 139337, 140067, 140068, 140069, 140070, 140071, 140072, 140442, 140613);

  script_name(english:"SUSE SLES11 Security Update : ImageMagick (SUSE-SU-2016:1782-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ImageMagick was updated to fix 55 security issues.

These security issues were fixed :

  - CVE-2014-9810: SEGV in dpx file handler (bsc#983803).

  - CVE-2014-9811: Crash in xwd file handler (bsc#984032).

  - CVE-2014-9812: NULL pointer dereference in ps file
    handling (bsc#984137).

  - CVE-2014-9813: Crash on corrupted viff file
    (bsc#984035).

  - CVE-2014-9814: NULL pointer dereference in wpg file
    handling (bsc#984193).

  - CVE-2014-9815: Crash on corrupted wpg file (bsc#984372).

  - CVE-2014-9816: Out of bound access in viff image
    (bsc#984398).

  - CVE-2014-9817: Heap buffer overflow in pdb file handling
    (bsc#984400).

  - CVE-2014-9818: Out of bound access on malformed sun file
    (bsc#984181).

  - CVE-2014-9819: Heap overflow in palm files (bsc#984142).

  - CVE-2014-9830: Handling of corrupted sun file
    (bsc#984135).

  - CVE-2014-9831: Handling of corrupted wpg file
    (bsc#984375).

  - CVE-2014-9836: Crash in xpm file handling (bsc#984023).

  - CVE-2014-9851: Crash when parsing resource block
    (bsc#984160).

  - CVE-2016-5689: NULL ptr dereference in dcm coder
    (bsc#985460).

  - CVE-2014-9853: Memory leak in rle file handling
    (bsc#984408).

  - CVE-2015-8902: PDB file DoS (CPU consumption)
    (bsc#983253).

  - CVE-2015-8903: Denial of service (cpu) in vicar
    (bsc#983259).

  - CVE-2015-8901: MIFF file DoS (endless loop)
    (bsc#983234).

  - CVE-2014-9834: Heap overflow in pict file (bsc#984436).

  - CVE-2014-9806: Prevent file descriptr leak due to
    corrupted file (bsc#983774).

  - CVE-2014-9838: Out of memory crash in magick/cache.c
    (bsc#984370).

  - CVE-2014-9854: Filling memory during identification of
    TIFF image (bsc#984184).

  - CVE-2015-8898: Prevent NULL pointer access in
    magick/constitute.c (bsc#983746).

  - CVE-2015-8894: Double free in coders/tga.c:221
    (bsc#983523).

  - CVE-2015-8896: Double free / integer truncation issue in
    coders/pict.c:2000 (bsc#983533).

  - CVE-2015-8897: Out of bounds error in SpliceImage
    (bsc#983739).

  - CVE-2016-5690: Bad foor loop in DCM coder (bsc#985451).

  - CVE-2016-5691: Checks for pixel.red/green/blue in dcm
    coder (bsc#985456).

  - CVE-2014-9805: SEGV due to a corrupted pnm file.
    (bsc#983752).

  - CVE-2014-9808: SEGV due to corrupted dpc images.
    (bsc#983796).

  - CVE-2014-9820: heap overflow in xpm files (bsc#984150).

  - CVE-2014-9823: heap overflow in palm file (bsc#984401).

  - CVE-2014-9822: heap overflow in quantum file
    (bsc#984187).

  - CVE-2014-9839: Theoretical out of bound access in
    magick/colormap-private.h (bsc#984379).

  - CVE-2014-9824: Heap overflow in psd file (bsc#984185).

  - CVE-2014-9809: Fix a SEGV due to corrupted xwd images.
    (bsc#983799).

  - CVE-2014-9826: Incorrect error handling in sun files
    (bsc#984186).

  - CVE-2014-9842: Memory leak in psd handling (bsc#984374).

  - CVE-2016-5687: Out of bounds read in DDS coder
    (bsc#985448).

  - CVE-2014-9840: Out of bound access in palm file
    (bsc#984433).

  - CVE-2014-9847: Incorrect handling of 'previous' image in
    the JNG decoder (bsc#984144).

  - CVE-2014-9846: Added checks to prevent overflow in rle
    file. (bsc#983521).

  - CVE-2014-9845: Crash due to corrupted dib file
    (bsc#984394).

  - CVE-2014-9844: Out of bound issue in rle file
    (bsc#984373).

  - CVE-2014-9849: Crash in png coder (bsc#984018).

  - CVE-2016-5688: Various invalid memory reads in
    ImageMagick WPG (bsc#985442).

  - CVE-2014-9807: Fix a double free in pdb coder.
    (bsc#983794).

  - CVE-2014-9829: Out of bound access in sun file
    (bsc#984409).

  - CVE-2016-4564: The DrawImage function in
    MagickCore/draw.c in ImageMagick made an incorrect
    function call in attempting to locate the next token,
    which allowed remote attackers to cause a denial of
    service (buffer overflow and application crash) or
    possibly have unspecified other impact via a crafted
    file (bsc#983308).

  - CVE-2016-4563: The TraceStrokePolygon function in
    MagickCore/draw.c in ImageMagick mishandled the
    relationship between the BezierQuantum value and certain
    strokes data, which allowed remote attackers to cause a
    denial of service (buffer overflow and application
    crash) or possibly have unspecified other impact via a
    crafted file (bsc#983305).

  - CVE-2016-4562: The DrawDashPolygon function in
    MagickCore/draw.c in ImageMagick mishandled calculations
    of certain vertices integer data, which allowed remote
    attackers to cause a denial of service (buffer overflow
    and application crash) or possibly have unspecified
    other impact via a crafted file (bsc#983292).

  - CVE-2014-9837: Additional PNM sanity checks
    (bsc#984166).

  - CVE-2014-9835: Heap overflow in wpf file (bsc#984145).

  - CVE-2014-9828: Corrupted (too many colors) psd file
    (bsc#984028).

  - CVE-2016-5841: Integer overflow could have read to RCE
    (bnc#986609).

  - CVE-2016-5842: Out-of-bounds read in
    MagickCore/property.c:1396 could have lead to memory
    leak (bnc#986608).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984035"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984144"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984184"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984187"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984400"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9806.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9807.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9808.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9809.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9810.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9811.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9812.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9813.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9814.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9815.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9816.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9817.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9818.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9819.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9820.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9822.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9823.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9824.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9826.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9828.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9829.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9830.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9831.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9834.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9836.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9837.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9838.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9839.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9840.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9842.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9844.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9845.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9846.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9847.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9849.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9851.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9853.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9854.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8894.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8896.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8897.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8898.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8901.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8902.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8903.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4562.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4563.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4564.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5687.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5688.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5689.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5690.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5691.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5842.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161782-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9cbc9ade"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 11-SP4 :

zypper in -t patch sdksp4-ImageMagick-12643=1

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-ImageMagick-12643=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-ImageMagick-12643=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libMagickCore1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", cpu:"x86_64", reference:"libMagickCore1-32bit-6.4.3.6-7.45.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", cpu:"s390x", reference:"libMagickCore1-32bit-6.4.3.6-7.45.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"libMagickCore1-6.4.3.6-7.45.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick");
}
