#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80822);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:24:31 $");

  script_cve_id("CVE-2013-1981", "CVE-2013-1982", "CVE-2013-1984", "CVE-2013-1985", "CVE-2013-1995", "CVE-2013-1996", "CVE-2013-1997", "CVE-2013-1998", "CVE-2013-2002", "CVE-2013-2004", "CVE-2013-2005", "CVE-2013-2062");

  script_name(english:"Oracle Solaris Third-Party Patch Update : xorg (multiple_vulnerabilities_in_x_org1)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - Multiple integer overflows in X.org libX11 1.5.99.901
    (1.6 RC1) and earlier allow X servers to trigger
    allocation of insufficient memory and a buffer overflow
    via vectors related to the (1) XQueryFont, (2)
    _XF86BigfontQueryFont, (3) XListFontsWithInfo, (4)
    XGetMotionEvents, (5) XListHosts, (6)
    XGetModifierMapping, (7) XGetPointerMapping, (8)
    XGetKeyboardMapping, (9) XGetWindowProperty, (10)
    XGetImage, (11) LoadColornameDB, (12)
    XrmGetFileDatabase, (13) _XimParseStringFile, or (14)
    TransFileName functions. (CVE-2013-1981)

  - Multiple integer overflows in X.org libXext 1.3.1 and
    earlier allow X servers to trigger allocation of
    insufficient memory and a buffer overflow via vectors
    related to the (1) XcupGetReservedColormapEntries, (2)
    XcupStoreColors, (3) XdbeGetVisualInfo, (4)
    XeviGetVisualInfo, (5) XShapeGetRectangles, and (6)
    XSyncListSystemCounters functions. (CVE-2013-1982)

  - Multiple integer overflows in X.org libXi 1.7.1 and
    earlier allow X servers to trigger allocation of
    insufficient memory and a buffer overflow via vectors
    related to the (1) XGetDeviceControl, (2)
    XGetFeedbackControl, (3) XGetDeviceDontPropagateList,
    (4) XGetDeviceMotionEvents, (5) XIGetProperty, (6)
    XIGetSelectedEvents, (7) XGetDeviceProperties, and (8)
    XListInputDevices functions. (CVE-2013-1984)

  - Integer overflow in X.org libXinerama 1.1.2 and earlier
    allows X servers to trigger allocation of insufficient
    memory and a buffer overflow via vectors related to the
    XineramaQueryScreens function. (CVE-2013-1985)

  - X.org libXi 1.7.1 and earlier allows X servers to
    trigger allocation of insufficient memory and a buffer
    overflow via vectors related to an unexpected sign
    extension in the XListInputDevices function.
    (CVE-2013-1995)

  - X.org libFS 1.0.4 and earlier allows X servers to
    trigger allocation of insufficient memory and a buffer
    overflow via vectors related to an unexpected sign
    extension in the FSOpenServer function. (CVE-2013-1996)

  - Multiple buffer overflows in X.org libX11 1.5.99.901
    (1.6 RC1) and earlier allow X servers to cause a denial
    of service (crash) and possibly execute arbitrary code
    via crafted length or index values to the (1)
    XAllocColorCells, (2) _XkbReadGetDeviceInfoReply, (3)
    _XkbReadGeomShapes, (4) _XkbReadGetGeometryReply, (5)
    _XkbReadKeySyms, (6) _XkbReadKeyActions, (7)
    _XkbReadKeyBehaviors, (8) _XkbReadModifierMap, (9)
    _XkbReadExplicitComponents, (10) _XkbReadVirtualModMap,
    (11) _XkbReadGetNamesReply, (12) _XkbReadGetMapReply,
    (13) _XimXGetReadData, (14) XListFonts, (15)
    XListExtensions, and (16) XGetFontPath functions.
    (CVE-2013-1997)

  - Multiple buffer overflows in X.org libXi 1.7.1 and
    earlier allow X servers to cause a denial of service
    (crash) and possibly execute arbitrary code via crafted
    length or index values to the (1)
    XGetDeviceButtonMapping, (2) XIPassiveGrabDevice, and
    (3) XQueryDeviceState functions. (CVE-2013-1998)

  - Buffer overflow in X.org libXt 1.1.3 and earlier allows
    X servers to cause a denial of service (crash) and
    possibly execute arbitrary code via crafted length or
    index values to the _XtResourceConfigurationEH function.
    (CVE-2013-2002)

  - The (1) GetDatabase and (2) _XimParseStringFile
    functions in X.org libX11 1.5.99.901 (1.6 RC1) and
    earlier do not restrict the recursion depth when
    processing directives to include files, which allows X
    servers to cause a denial of service (stack consumption)
    via a crafted file. (CVE-2013-2004)

  - X.org libXt 1.1.3 and earlier does not check the return
    value of the XGetWindowProperty function, which allows X
    servers to trigger use of an uninitialized pointer and
    memory corruption via vectors related to the (1)
    ReqCleanup, (2) HandleSelectionEvents, (3) ReqTimedOut,
    (4) HandleNormal, and (5) HandleSelectionReplies
    functions. (CVE-2013-2005)

  - Multiple integer overflows in X.org libXp 1.0.1 and
    earlier allow X servers to trigger allocation of
    insufficient memory and a buffer overflow via vectors
    related to the (1) XpGetAttributes, (2)
    XpGetOneAttribute, (3) XpGetPrinterList, and (4)
    XpQueryScreens functions. (CVE-2013-2062)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_x_org1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ba51a66"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.8.4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:xorg");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^xorg$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.8.0.4.0", sru:"SRU 11.1.8.4.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : xorg\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "xorg");
