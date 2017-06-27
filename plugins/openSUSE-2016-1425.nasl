#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1425.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95649);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/12/08 20:42:13 $");

  script_cve_id("CVE-2014-8127", "CVE-2015-7554", "CVE-2015-8665", "CVE-2015-8683", "CVE-2016-3622", "CVE-2016-3658", "CVE-2016-5321", "CVE-2016-5323", "CVE-2016-5652", "CVE-2016-5875", "CVE-2016-9273", "CVE-2016-9297", "CVE-2016-9448", "CVE-2016-9453");

  script_name(english:"openSUSE Security Update : tiff (openSUSE-2016-1425)");
  script_summary(english:"Check for the openSUSE-2016-1425 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tiff was updated to version 4.0.7. This update fixes the following
issues :

  - libtiff/tif_aux.c

  + Fix crash in TIFFVGetFieldDefaulted() when requesting
    Predictor tag and that the zip/lzw codec is not
    configured.
    (http://bugzilla.maptools.org/show_bug.cgi?id=2591)

  - libtiff/tif_compress.c

  + Make TIFFNoDecode() return 0 to indicate an error and
    make upper level read routines treat it accordingly.
    (http://bugzilla.maptools.org/show_bug.cgi?id=2517)

  - libtiff/tif_dir.c

  + Discard values of SMinSampleValue and SMaxSampleValue
    when they have been read and the value of
    SamplesPerPixel is changed afterwards (like when reading
    a OJPEG compressed image with a missing SamplesPerPixel
    tag, and whose photometric is RGB or YCbCr, forcing
    SamplesPerPixel being 3). Otherwise when rewriting the
    directory (for example with tiffset, we will expect 3
    values whereas the array had been allocated with just
    one), thus causing a out of bound read access.
    (CVE-2014-8127, boo#914890, duplicate: CVE-2016-3658,
    boo#974840)

  - libtiff/tif_dirread.c

  + In TIFFFetchNormalTag(), do not dereference NULL pointer
    when values of tags with
    TIFF_SETGET_C16_ASCII/TIFF_SETGET_C32_ASCII access are
    0-byte arrays. (CVE-2016-9448, boo#1011103)

  + In TIFFFetchNormalTag(), make sure that values of tags
    with TIFF_SETGET_C16_ASCII/TIFF_SETGET_C32_ASCII access
    are null terminated, to avoid potential read outside
    buffer in _TIFFPrintField(). (CVE-2016-9297,
    boo#1010161)

  + Prevent reading ColorMap or TransferFunction if
    BitsPerPixel > 24, so as to avoid huge memory allocation
    and file read attempts

  + Reject images with OJPEG compression that have no
    TileOffsets/StripOffsets tag, when OJPEG compression is
    disabled. Prevent NULL pointer dereference in
    TIFFReadRawStrip1() and other functions that expect
    td_stripbytecount to be non NULL.
    (http://bugzilla.maptools.org/show_bug.cgi?id=2585)

  + When compiled with DEFER_STRILE_LOAD, fix regression,
    when reading a one-strip file without a StripByteCounts
    tag.

  + Workaround false positive warning of Clang Static
    Analyzer about NULL pointer dereference in
    TIFFCheckDirOffset().

  - libtiff/tif_dirwrite.c

  + Avoid NULL pointer dereference on td_stripoffset when
    writing directory, if FIELD_STRIPOFFSETS was
    artificially set for a hack case in OJPEG case. Fixes
    (CVE-2014-8127, boo#914890, duplicate: CVE-2016-3658,
    boo#974840)

  + Fix truncation to 32 bit of file offsets in
    TIFFLinkDirectory() and TIFFWriteDirectorySec() when
    aligning directory offsets on an even offset (affects
    BigTIFF).

  - libtiff/tif_dumpmode.c

  + DumpModeEncode() should return 0 in case of failure so
    that the above mentionned functions detect the error.

  - libtiff/tif_fax3.c

  + remove dead assignment in Fax3PutEOLgdal().

  - libtiff/tif_fax3.h

  + make Param member of TIFFFaxTabEnt structure a uint16 to
    reduce size of the binary.

  - libtiff/tif_getimage.c

  + Fix out-of-bound reads in TIFFRGBAImage interface in
    case of unsupported values of
    SamplesPerPixel/ExtraSamples for LogLUV/CIELab. Add
    explicit call to TIFFRGBAImageOK() in
    TIFFRGBAImageBegin(). Fix CVE-2015-8665 and
    CVE-2015-8683.

  + TIFFRGBAImageOK: Reject attempts to read floating point
    images.

  - libtiff/tif_luv.c

  + Fix potential out-of-bound writes in decode functions in
    non debug builds by replacing assert()s by regular if
    checks
    (http://bugzilla.maptools.org/show_bug.cgi?id=2522). Fix
    potential out-of-bound reads in case of short input
    data.

  + Validate that for COMPRESSION_SGILOG and
    PHOTOMETRIC_LOGL, there is only one sample per pixel.
    Avoid potential invalid memory write on
    corrupted/unexpected images when using the
    TIFFRGBAImageBegin() interface

  - libtiff/tif_next.c

  + Fix potential out-of-bound write in NeXTDecode()
    (http://bugzilla.maptools.org/show_bug.cgi?id=2508)

  - libtiff/tif_pixarlog.c

  + Avoid zlib error messages to pass a NULL string to %s
    formatter, which is undefined behaviour in sprintf().

  + Fix out-of-bounds write vulnerabilities in heap
    allocated buffers. Reported as MSVR 35094.

  + Fix potential buffer write overrun in PixarLogDecode()
    on corrupted/unexpected images (CVE-2016-5875,
    boo#987351)

  - libtiff/tif_predict.c

  + PredictorSetup: Enforce bits-per-sample requirements of
    floating point predictor (3). (CVE-2016-3622,
    boo#974449)

  - libtiff/tif_predict.h, libtiff/tif_predict.c

  + Replace assertions by runtime checks to avoid assertions
    in debug mode, or buffer overflows in release mode. Can
    happen when dealing with unusual tile size like YCbCr
    with subsampling. Reported as MSVR 35105.

  - libtiff/tif_read.c

  + Fix out-of-bounds read on memory-mapped files in
    TIFFReadRawStrip1() and TIFFReadRawTile1() when
    stripoffset is beyond tmsize_t max value

  + Make TIFFReadEncodedStrip() and TIFFReadEncodedTile()
    directly use user provided buffer when no compression
    (and other conditions) to save a memcpy().

  - libtiff/tif_strip.c

  + Make TIFFNumberOfStrips() return the td->td_nstrips
    value when it is non-zero, instead of recomputing it.
    This is needed in TIFF_STRIPCHOP mode where td_nstrips
    is modified. Fixes a read outsize of array in tiffsplit
    (or other utilities using TIFFNumberOfStrips()).
    (CVE-2016-9273, boo#1010163)

  - libtiff/tif_write.c

  + Fix issue in error code path of TIFFFlushData1() that
    didn't reset the tif_rawcc and tif_rawcp members. I'm
    not completely sure if that could happen in practice
    outside of the odd behaviour of t2p_seekproc() of
    tiff2pdf). The report points that a better fix could be
    to check the return value of TIFFFlushData1() in places
    where it isn't done currently, but it seems this patch
    is enough. Reported as MSVR 35095.

  + Make TIFFWriteEncodedStrip() and TIFFWriteEncodedTile()
    directly use user provided buffer when no compression to
    save a memcpy().

  + TIFFWriteEncodedStrip() and TIFFWriteEncodedTile()
    should return -1 in case of failure of tif_encodestrip()
    as documented

  - tools/fax2tiff.c

  + Fix segfault when specifying -r without argument.
    (http://bugzilla.maptools.org/show_bug.cgi?id=2572)

  - tools/Makefile.am

  + The libtiff tools bmp2tiff, gif2tiff, ras2tiff,
    sgi2tiff, sgisv, and ycbcr are completely removed from
    the distribution. The libtiff tools rgb2ycbcr and
    thumbnail are only built in the build tree for testing.
    Old files are put in new 'archive' subdirectory of the
    source repository, but not in distribution archives.
    These changes are made in order to lessen the
    maintenance burden.

  - tools/tiff2bw.c

  + Fix weight computation that could result of color value
    overflow (no security implication). Fix
    http://bugzilla.maptools.org/show_bug.cgi?id=2550.

  - tools/tiff2pdf.c

  + Avoid undefined behaviour related to overlapping of
    source and destination buffer in memcpy() call in
    t2p_sample_rgbaa_to_rgb()
    (http://bugzilla.maptools.org/show_bug.cgi?id=2577)

  + Fix out-of-bounds write vulnerabilities in heap allocate
    buffer in t2p_process_jpeg_strip(). Reported as MSVR
    35098.

  + Fix potential integer overflows on 32 bit builds in
    t2p_read_tiff_size()
    (http://bugzilla.maptools.org/show_bug.cgi?id=2576)

  + Fix read -largely- outsize of buffer in
    t2p_readwrite_pdf_image_tile(), causing crash, when
    reading a JPEG compressed image with TIFFTAG_JPEGTABLES
    length being one. (CVE-2016-9453, boo#1011107)

  + Fix write buffer overflow of 2 bytes on JPEG compressed
    images. Also prevents writing 2 extra uninitialized
    bytes to the file stream. (TALOS-CAN-0187,
    CVE-2016-5652, boo#1007280)

  - tools/tiffcp.c

  + Fix out-of-bounds write on tiled images with odd tile
    width vs image width. Reported as MSVR 35103.

  + Fix read of undefined variable in case of missing
    required tags. Found on test case of MSVR 35100.

  - tools/tiffcrop.c

  + Avoid access outside of stack allocated array on a tiled
    separate TIFF with more than 8 samples per pixel.
    (CVE-2016-5321, CVE-2016-5323, boo#984813, boo#984815)

  + Fix memory leak in (recent) error code path.

  + Fix multiple uint32 overflows in
    writeBufferToSeparateStrips(),
    writeBufferToContigTiles() and
    writeBufferToSeparateTiles() that could cause heap
    buffer overflows.
    (http://bugzilla.maptools.org/show_bug.cgi?id=2592)

  + Fix out-of-bound read of up to 3 bytes in
    readContigTilesIntoBuffer(). Reported as MSVR 35092.

  + Fix read of undefined buffer in
    readContigStripsIntoBuffer() due to uint16 overflow.
    Reported as MSVR 35100.

  + Fix various out-of-bounds write vulnerabilities in heap
    or stack allocated buffers. Reported as MSVR 35093, MSVR
    35096 and MSVR 35097.

  + readContigTilesIntoBuffer: Fix signed/unsigned
    comparison warning.

  - tools/tiffdump.c

  + Fix a few misaligned 64-bit reads warned by -fsanitize

  + ReadDirectory: Remove uint32 cast to_TIFFmalloc()
    argument which resulted in Coverity report. Added more
    mutiplication overflow checks

  - tools/tiffinfo.c

  + Fix out-of-bound read on some tiled images.
    (http://bugzilla.maptools.org/show_bug.cgi?id=2517)

  + TIFFReadContigTileData: Fix signed/unsigned comparison
    warning.

  + TIFFReadSeparateTileData: Fix signed/unsigned comparison
    warning."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.maptools.org/show_bug.cgi?id=2508"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.maptools.org/show_bug.cgi?id=2517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.maptools.org/show_bug.cgi?id=2522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.maptools.org/show_bug.cgi?id=2550."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.maptools.org/show_bug.cgi?id=2572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.maptools.org/show_bug.cgi?id=2576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.maptools.org/show_bug.cgi?id=2577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.maptools.org/show_bug.cgi?id=2585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.maptools.org/show_bug.cgi?id=2591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.maptools.org/show_bug.cgi?id=2592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=914890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987351"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libtiff5-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tiff-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"libtiff-devel-4.0.7-10.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtiff5-4.0.7-10.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libtiff5-debuginfo-4.0.7-10.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tiff-4.0.7-10.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tiff-debuginfo-4.0.7-10.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"tiff-debugsource-4.0.7-10.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtiff-devel-32bit-4.0.7-10.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtiff5-32bit-4.0.7-10.35.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"libtiff5-debuginfo-32bit-4.0.7-10.35.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff-devel-32bit / libtiff-devel / libtiff5-32bit / libtiff5 / etc");
}
