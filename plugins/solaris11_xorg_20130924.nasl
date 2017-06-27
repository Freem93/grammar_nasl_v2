#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80819);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:24:31 $");

  script_cve_id("CVE-2013-1983", "CVE-2013-1986", "CVE-2013-1987", "CVE-2013-1988", "CVE-2013-1989", "CVE-2013-1990", "CVE-2013-1992", "CVE-2013-1993", "CVE-2013-1999", "CVE-2013-2000", "CVE-2013-2001", "CVE-2013-2003", "CVE-2013-2063", "CVE-2013-2064", "CVE-2013-2066");

  script_name(english:"Oracle Solaris Third-Party Patch Update : xorg (multiple_vulnerabilities_in_x_org)");
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

  - Integer overflow in X.org libXfixes 5.0 and earlier
    allows X servers to trigger allocation of insufficient
    memory and a buffer overflow via vectors related to the
    XFixesGetCursorImage function. (CVE-2013-1983)

  - Multiple integer overflows in X.org libXrandr 1.4.0 and
    earlier allow X servers to trigger allocation of
    insufficient memory and a buffer overflow via vectors
    related to the (1) XRRQueryOutputProperty and (2)
    XRRQueryProviderProperty functions. (CVE-2013-1986)

  - Multiple integer overflows in X.org libXrender 0.9.7 and
    earlier allow X servers to trigger allocation of
    insufficient memory and a buffer overflow via vectors
    related to the (1) XRenderQueryFilters, (2)
    XRenderQueryFormats, and (3) XRenderQueryPictIndexValues
    functions. (CVE-2013-1987)

  - Multiple integer overflows in X.org libXRes 1.0.6 and
    earlier allow X servers to trigger allocation of
    insufficient memory and a buffer overflow via vectors
    related to the (1) XResQueryClients and (2)
    XResQueryClientResources functions. (CVE-2013-1988)

  - Multiple integer overflows in X.org libXv 1.0.7 and
    earlier allow X servers to trigger allocation of
    insufficient memory and a buffer overflow via vectors
    related to the (1) XvQueryPortAttributes, (2)
    XvListImageFormats, and (3) XvCreateImage function.
    (CVE-2013-1989)

  - Multiple integer overflows in X.org libXvMC 1.0.7 and
    earlier allow X servers to trigger allocation of
    insufficient memory and a buffer overflow via vectors
    related to the (1) XvMCListSurfaceTypes and (2)
    XvMCListSubpictureTypes functions. (CVE-2013-1990)

  - Multiple integer overflows in X.org libdmx 1.1.2 and
    earlier allow X servers to trigger allocation of
    insufficient memory and a buffer overflow via vectors
    related to the (1) DMXGetScreenAttributes, (2)
    DMXGetWindowAttributes, and (3) DMXGetInputAttributes
    functions. (CVE-2013-1992)

  - Multiple integer overflows in X.org libGLX in Mesa 9.1.1
    and earlier allow X servers to trigger allocation of
    insufficient memory and a buffer overflow via vectors
    related to the (1) XF86DRIOpenConnection and (2)
    XF86DRIGetClientDriverName functions. (CVE-2013-1993)

  - Buffer overflow in X.org libXvMC 1.0.7 and earlier
    allows X servers to cause a denial of service (crash)
    and possibly execute arbitrary code via crafted length
    or index values to the XvMCGetDRInfo function.
    (CVE-2013-1999)

  - Multiple buffer overflows in X.org libXxf86dga 1.1.3 and
    earlier allow X servers to cause a denial of service
    (crash) and possibly execute arbitrary code via crafted
    length or index values to the (1) XDGAQueryModes and (2)
    XDGASetMode functions. (CVE-2013-2000)

  - Buffer overflow in X.org libXxf86vm 1.1.2 and earlier
    allows X servers to cause a denial of service (crash)
    and possibly execute arbitrary code via crafted length
    or index values to the XF86VidModeGetGammaRamp function.
    (CVE-2013-2001)

  - Integer overflow in X.org libXcursor 1.1.13 and earlier
    allows X servers to trigger allocation of insufficient
    memory and a buffer overflow via vectors related to the
    _XcursorFileHeaderCreate function. (CVE-2013-2003)

  - Integer overflow in X.org libXtst 1.2.1 and earlier
    allows X servers to trigger allocation of insufficient
    memory and a buffer overflow via vectors related to the
    XRecordGetContext function. (CVE-2013-2063)

  - Integer overflow in X.org libxcb 1.9 and earlier allows
    X servers to trigger allocation of insufficient memory
    and a buffer overflow via vectors related to the
    read_packet function. (CVE-2013-2064)

  - Buffer overflow in X.org libXv 1.0.7 and earlier allows
    X servers to cause a denial of service (crash) and
    possibly execute arbitrary code via crafted length or
    index values to the XvQueryPortAttributes function.
    (CVE-2013-2066)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_x_org
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4e5e42c"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.8.4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:xorg");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
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
